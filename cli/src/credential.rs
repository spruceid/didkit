use std::io::{stdin, stdout, BufReader, BufWriter, Read};

use anyhow::Result;
use clap::{Args, Subcommand};
use didkit::{
    generate_proof, ContextLoader, LinkedDataProofOptions, ProofFormat, VerifiableCredential, JWK,
};
use tracing::warn;

use crate::{get_ssh_agent_sock, opts::ResolverOptions, KeyArg, ProofOptions};

#[derive(Subcommand)]
pub enum CredentialCmd {
    /// Issue Credential
    Issue(Box<CredentialIssueArgs>),
    /// Verify Credential
    Verify(CredentialVerifyArgs),
}

#[derive(Args)]
pub struct CredentialIssueArgs {
    #[clap(flatten)]
    key: KeyArg,
    #[clap(flatten)]
    proof_options: ProofOptions,
    #[clap(flatten)]
    resolver_options: ResolverOptions,
}

#[derive(Args)]
pub struct CredentialVerifyArgs {
    #[clap(flatten)]
    proof_options: ProofOptions,
    #[clap(flatten)]
    resolver_options: ResolverOptions,
}

pub async fn cli(cmd: CredentialCmd) -> Result<()> {
    match cmd {
        CredentialCmd::Issue(cmd_issue) => issue(*cmd_issue).await?,
        CredentialCmd::Verify(cmd_verify) => verify(cmd_verify).await?,
    };
    Ok(())
}

pub async fn issue(args: CredentialIssueArgs) -> Result<()> {
    let resolver = args.resolver_options.to_resolver();
    let mut context_loader = ContextLoader::default();
    let credential_reader = BufReader::new(stdin());
    let mut credential: VerifiableCredential = serde_json::from_reader(credential_reader).unwrap();
    let proof_format = args.proof_options.proof_format.clone();
    let jwk_opt: Option<JWK> = args.key.get_jwk_opt();
    let ssh_agent_sock_opt = if args.key.ssh_agent {
        Some(get_ssh_agent_sock())
    } else {
        None
    };
    let options = LinkedDataProofOptions::from(args.proof_options);
    match proof_format {
        ProofFormat::JWT => {
            if ssh_agent_sock_opt.is_some() {
                todo!("ssh-agent for JWT not implemented");
            }
            let jwt = credential
                .generate_jwt(jwk_opt.as_ref(), &options, &resolver)
                .await
                .unwrap();
            print!("{jwt}");
        }
        ProofFormat::LDP => {
            let proof = generate_proof(
                &credential,
                jwk_opt.as_ref(),
                options,
                &resolver,
                &mut context_loader,
                ssh_agent_sock_opt.as_deref(),
            )
            .await
            .unwrap();
            credential.add_proof(proof);
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer(stdout_writer, &credential).unwrap();
        }
        _ => {
            panic!("Unknown proof format: {:?}", proof_format);
        }
    }
    Ok(())
}

pub async fn verify(args: CredentialVerifyArgs) -> Result<()> {
    let resolver = args.resolver_options.to_resolver();
    let mut context_loader = ContextLoader::default();
    let mut credential_reader = BufReader::new(stdin());
    let proof_format = args.proof_options.proof_format.clone();
    let options = LinkedDataProofOptions::from(args.proof_options);
    let result = match proof_format {
        ProofFormat::JWT => {
            let mut jwt = String::new();
            credential_reader.read_to_string(&mut jwt).unwrap();
            let trimmed_jwt = jwt.trim();
            if jwt != trimmed_jwt {
                warn!("JWT was trimmed for extraneous whitespaces and new lines.");
            }
            VerifiableCredential::verify_jwt(
                trimmed_jwt,
                Some(options),
                &resolver,
                &mut context_loader,
            )
            .await
        }
        ProofFormat::LDP => {
            let credential: VerifiableCredential =
                serde_json::from_reader(credential_reader).unwrap();
            credential.validate_unsigned().unwrap();
            credential
                .verify(Some(options), &resolver, &mut context_loader)
                .await
        }
        _ => {
            panic!("Unknown proof format: {:?}", proof_format);
        }
    };

    let stdout_writer = BufWriter::new(stdout());
    serde_json::to_writer(stdout_writer, &result).unwrap();
    if !result.errors.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}
