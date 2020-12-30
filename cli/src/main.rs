use std::fs::File;
use std::io::{stdin, stdout, BufReader, BufWriter};
use std::path::PathBuf;

use async_std::task::block_on;
use chrono::prelude::*;
use structopt::{clap::ArgGroup, StructOpt};

use didkit::{
    LinkedDataProofOptions, ProofPurpose, VerifiableCredential, VerifiablePresentation, JWK,
};

#[derive(StructOpt, Debug)]
pub enum DIDKit {
    /// Generate and output a Ed25519 keypair in JWK format
    GenerateEd25519Key,
    /// Output a did:key DID for a JWK
    KeyToDIDKey {
        #[structopt(flatten)]
        key: KeyArg,
    },
    /// Output a verificationMethod for a JWK
    KeyToVerificationMethod {
        #[structopt(flatten)]
        key: KeyArg,
    },

    /*
    // DID Functionality
    /// Create new DID Document.
    DIDCreate {},
    /// Resolve a DID to a DID Document.
    DIDResolve {},
    /// Dereference a DID URL to a resource.
    DIDDereference {},
    /// Update a DID Document’s authentication.
    DIDUpdateAuthentication {},
    /// Update a DID Document’s service endpoint(s).
    DIDUpdateServiceEndpoints {},
    /// Deactivate a DID.
    DIDDeactivate {},
    /// Create a Signed IETF JSON Patch to update a DID document.
    DIDPatch {},
    */
    // VC Functionality
    /// Issue Credential
    VCIssueCredential {
        #[structopt(flatten)]
        key: KeyArg,
        #[structopt(flatten)]
        proof_options: ProofOptions,
    },
    /// Verify Credential
    VCVerifyCredential {
        #[structopt(flatten)]
        proof_options: ProofOptions,
    },
    /// Issue Presentation
    VCIssuePresentation {
        #[structopt(flatten)]
        key: KeyArg,
        #[structopt(flatten)]
        proof_options: ProofOptions,
    },
    /// Verify Presentation
    VCVerifyPresentation {
        #[structopt(flatten)]
        proof_options: ProofOptions,
    },
    /*
    /// Revoke Credential
    VCRevokeCredential {},
    */

    /*
    // DIDComm Functionality (???)
    /// Discover a messaging endpoint from a DID which supports DIDComm.
    DIDCommDiscover {},
    /// Send a DIDComm message.
    DIDCommSend {},
    /// Receive a DIDComm message.
    DIDCommReceive {},
    */
}

#[derive(StructOpt, Debug)]
pub struct ProofOptions {
    #[structopt(env, short, long)]
    pub verification_method: Option<String>,
    #[structopt(env, short, long)]
    pub proof_purpose: Option<ProofPurpose>,
    #[structopt(env, short, long)]
    pub created: Option<DateTime<Utc>>,
    #[structopt(env, short = "C", long)]
    pub challenge: Option<String>,
    #[structopt(env, short, long)]
    pub domain: Option<String>,
}

#[derive(StructOpt, Debug)]
#[structopt(group = ArgGroup::with_name("key_group").required(true))]
pub struct KeyArg {
    #[structopt(env, short, long, parse(from_os_str), group = "key_group")]
    key_path: Option<PathBuf>,
    #[structopt(
        env,
        short,
        long,
        parse(try_from_str = serde_json::from_str),
        conflicts_with = "key_path",
        group = "key_group",
        help = "WARNING: you should not use this through the CLI in a production environment, prefer its environment variable."
    )]
    jwk: Option<JWK>,
}

impl KeyArg {
    fn get_jwk(&self) -> JWK {
        match &self.key_path {
            Some(p) => {
                let key_file = File::open(p).unwrap();
                let key_reader = BufReader::new(key_file);
                serde_json::from_reader(key_reader).unwrap()
            }
            None => self.jwk.clone().unwrap(),
        }
    }
}

impl From<ProofOptions> for LinkedDataProofOptions {
    fn from(options: ProofOptions) -> LinkedDataProofOptions {
        LinkedDataProofOptions {
            verification_method: options.verification_method,
            proof_purpose: options.proof_purpose,
            created: options.created,
            challenge: options.challenge,
            domain: options.domain,
            checks: None,
        }
    }
}

fn main() {
    let opt = DIDKit::from_args();
    match opt {
        DIDKit::GenerateEd25519Key => {
            let jwk = JWK::generate_ed25519().unwrap();
            let jwk_str = serde_json::to_string(&jwk).unwrap();
            println!("{}", jwk_str);
        }

        DIDKit::KeyToDIDKey { key } => {
            let did = key.get_jwk().to_did().unwrap();
            println!("{}", did);
        }

        DIDKit::KeyToVerificationMethod { key } => {
            let did = key.get_jwk().to_verification_method().unwrap();
            println!("{}", did);
        }

        DIDKit::VCIssueCredential { key, proof_options } => {
            let key: JWK = key.get_jwk();
            let credential_reader = BufReader::new(stdin());
            let mut credential: VerifiableCredential =
                serde_json::from_reader(credential_reader).unwrap();
            let options = LinkedDataProofOptions::from(proof_options);
            let proof = block_on(credential.generate_proof(&key, &options)).unwrap();
            credential.add_proof(proof);
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer(stdout_writer, &credential).unwrap();
        }

        DIDKit::VCVerifyCredential { proof_options } => {
            let credential_reader = BufReader::new(stdin());
            let credential: VerifiableCredential =
                serde_json::from_reader(credential_reader).unwrap();
            let options = LinkedDataProofOptions::from(proof_options);
            credential.validate_unsigned().unwrap();
            let result = block_on(credential.verify(Some(options)));
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer(stdout_writer, &result).unwrap();
            if result.errors.len() > 0 {
                std::process::exit(2);
            }
        }

        DIDKit::VCIssuePresentation { key, proof_options } => {
            let key: JWK = key.get_jwk();
            let presentation_reader = BufReader::new(stdin());
            let mut presentation: VerifiablePresentation =
                serde_json::from_reader(presentation_reader).unwrap();
            let options = LinkedDataProofOptions::from(proof_options);
            let proof = block_on(presentation.generate_proof(&key, &options)).unwrap();
            presentation.add_proof(proof);
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer(stdout_writer, &presentation).unwrap();
        }

        DIDKit::VCVerifyPresentation { proof_options } => {
            let presentation_reader = BufReader::new(stdin());
            let presentation: VerifiablePresentation =
                serde_json::from_reader(presentation_reader).unwrap();
            let options = LinkedDataProofOptions::from(proof_options);
            presentation.validate_unsigned().unwrap();
            let result = block_on(presentation.verify(Some(options)));
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer(stdout_writer, &result).unwrap();
            if result.errors.len() > 0 {
                std::process::exit(2);
            }
        }
    }
}
