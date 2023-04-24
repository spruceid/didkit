use std::io::{stdin, stdout, BufReader, BufWriter, Read};

use anyhow::Result;
use clap::{Args, Subcommand};
use didkit::{
    generate_proof, ContextLoader, LinkedDataProofOptions, ProofFormat, VerifiablePresentation, JWK,
};
use tracing::warn;

use crate::{get_ssh_agent_sock, opts::ResolverOptions, KeyArg, ProofOptions};

#[derive(Subcommand)]
pub enum PresentationCmd {
    /// Issue Presentation
    Issue(Box<PresentationIssueArgs>),
    /// Verify Presentation
    Verify(PresentationVerifyArgs),
}

#[derive(Args)]
pub struct PresentationIssueArgs {
    #[clap(flatten)]
    key: KeyArg,
    #[clap(flatten)]
    proof_options: ProofOptions,
    #[clap(flatten)]
    resolver_options: ResolverOptions,
}

#[derive(Args)]
pub struct PresentationVerifyArgs {
    #[clap(flatten)]
    resolver_options: ResolverOptions,
    #[clap(flatten)]
    proof_options: ProofOptions,
}

pub async fn cli(cmd: PresentationCmd) -> Result<()> {
    match cmd {
        PresentationCmd::Issue(cmd_issue) => issue(*cmd_issue).await?,
        PresentationCmd::Verify(cmd_verify) => verify(cmd_verify).await?,
    };
    Ok(())
}

pub async fn issue(args: PresentationIssueArgs) -> Result<()> {
    let resolver = args.resolver_options.to_resolver();
    let mut context_loader = ContextLoader::default();
    let presentation_reader = BufReader::new(stdin());
    let mut presentation: VerifiablePresentation =
        serde_json::from_reader(presentation_reader).unwrap();

    let jwk_opt: Option<JWK> = args.key.get_jwk_opt();
    let ssh_agent_sock_opt = if args.key.ssh_agent {
        Some(get_ssh_agent_sock())
    } else {
        None
    };
    let proof_format = args.proof_options.proof_format.clone();
    let options = LinkedDataProofOptions::from(args.proof_options);
    match proof_format {
        ProofFormat::JWT => {
            if ssh_agent_sock_opt.is_some() {
                todo!("ssh-agent for JWT not implemented");
            }
            let jwt = presentation
                .generate_jwt(jwk_opt.as_ref(), &options, &resolver)
                .await
                .unwrap();
            print!("{jwt}");
        }
        ProofFormat::LDP => {
            let proof = generate_proof(
                &presentation,
                jwk_opt.as_ref(),
                options,
                &resolver,
                &mut context_loader,
                ssh_agent_sock_opt.as_deref(),
            )
            .await
            .unwrap();
            presentation.add_proof(proof);
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer(stdout_writer, &presentation).unwrap();
        }
        _ => {
            panic!("Unexpected proof format: {:?}", proof_format);
        }
    }
    Ok(())
}

pub async fn verify(args: PresentationVerifyArgs) -> Result<()> {
    let resolver = args.resolver_options.to_resolver();
    let mut context_loader = ContextLoader::default();
    let mut presentation_reader = BufReader::new(stdin());
    let proof_format = args.proof_options.proof_format.clone();
    let options = LinkedDataProofOptions::from(args.proof_options);
    let result = match proof_format {
        ProofFormat::JWT => {
            let mut jwt = String::new();
            presentation_reader.read_to_string(&mut jwt).unwrap();
            let trimmed_jwt = jwt.trim();
            if jwt != trimmed_jwt {
                warn!("JWT was trimmed for extraneous whitespaces and new lines.");
            }
            VerifiablePresentation::verify_jwt(
                trimmed_jwt,
                Some(options),
                &resolver,
                &mut context_loader,
            )
            .await
        }
        ProofFormat::LDP => {
            let presentation: VerifiablePresentation =
                serde_json::from_reader(presentation_reader).unwrap();
            presentation.validate_unsigned().unwrap();
            presentation
                .verify(Some(options), &resolver, &mut context_loader)
                .await
        }
        _ => {
            panic!("Unexpected proof format: {:?}", proof_format);
        }
    };
    let stdout_writer = BufWriter::new(stdout());
    serde_json::to_writer(stdout_writer, &result).unwrap();
    if !result.errors.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}
