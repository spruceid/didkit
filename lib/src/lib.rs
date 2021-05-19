#[cfg(not(feature = "wasm"))]
pub mod c;
mod did_methods;
pub mod error;
#[cfg(not(feature = "wasm"))]
pub mod jni;
#[cfg(not(feature = "wasm"))]
pub mod runtime;
#[cfg(not(feature = "wasm"))]
pub mod ssh_agent;

#[macro_use]
extern crate lazy_static;

pub use crate::did_methods::DID_METHODS;
pub use crate::error::Error;
pub use ssi::did::{DIDMethod, Document, Source};
#[cfg(feature = "http-did")]
pub use ssi::did_resolve::HTTPDIDResolver;
pub use ssi::did_resolve::{
    dereference, Content, ContentMetadata, DIDResolver, DereferencingInputMetadata,
    DocumentMetadata, Metadata, ResolutionInputMetadata, ResolutionMetadata, ResolutionResult,
    SeriesResolver,
};
pub use ssi::jwk::JWK;
pub use ssi::ldp::resolve_key;
pub use ssi::ldp::ProofPreparation;
pub use ssi::vc::get_verification_method;
pub use ssi::vc::Credential as VerifiableCredential;
pub use ssi::vc::CredentialOrJWT;
pub use ssi::vc::LinkedDataProofOptions;
pub use ssi::vc::Presentation as VerifiablePresentation;
pub use ssi::vc::ProofPurpose;
pub use ssi::vc::VerificationResult;

use core::str::FromStr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct JWTOrLDPOptions {
    /// Linked data proof options from vc-http-api
    #[serde(flatten)]
    pub ldp_options: LinkedDataProofOptions,
    /// Proof format (not standard in vc-http-api)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_format: Option<ProofFormat>,
}

impl JWTOrLDPOptions {
    pub fn default_for_vp() -> Self {
        Self {
            ldp_options: LinkedDataProofOptions {
                proof_purpose: Some(ProofPurpose::Authentication),
                ..Default::default()
            },
            proof_format: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[non_exhaustive]
pub enum ProofFormat {
    /// <https://www.w3.org/TR/vc-data-model/#linked-data-proofs>
    #[serde(rename = "ldp")]
    LDP,
    /// <https://www.w3.org/TR/vc-data-model/#json-web-token>
    #[serde(rename = "jwt")]
    JWT,
}
// ProofFormat implements Display and FromStr for structopt. This should be kept in sync with the
// serde (de)serialization (rename = ...)

impl Default for ProofFormat {
    fn default() -> Self {
        Self::LDP
    }
}

impl std::fmt::Display for ProofFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LDP => write!(f, "ldp"),
            Self::JWT => write!(f, "jwt"),
        }
    }
}

impl FromStr for ProofFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..] {
            "ldp" => Ok(Self::LDP),
            "jwt" => Ok(Self::JWT),
            _ => Err(format!("Unexpected proof format: {}", s))?,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GenerateProofError {
    #[cfg(not(feature = "wasm"))]
    #[error("Unable to sign: {0}")]
    Sign(#[from] crate::ssh_agent::SignError),
    #[error("SSI: {0}")]
    SSI(#[from] ssi::error::Error),
    #[error("IO: {0}")]
    IO(#[from] std::io::Error),
    #[error("WASM support for ssh-agent is not enabled")]
    NoWASM,
}

pub async fn generate_proof(
    document: &(dyn ssi::ldp::LinkedDataDocument + Sync),
    key: Option<&JWK>,
    options: LinkedDataProofOptions,
    ssh_agent_sock_path_opt: Option<&str>,
) -> Result<ssi::vc::Proof, GenerateProofError> {
    use ssi::ldp::LinkedDataProofs;
    let proof = match ssh_agent_sock_path_opt {
        #[cfg(feature = "wasm")]
        Some(sock_path) => {
            return Err(GenerateProofError::NoWASM);
        }
        #[cfg(not(feature = "wasm"))]
        Some(sock_path) => {
            use tokio::net::UnixStream;
            let mut ssh_agent_sock = UnixStream::connect(sock_path).await?;
            crate::ssh_agent::generate_proof(&mut ssh_agent_sock, document, options, key).await?
        }
        None => {
            let jwk = key.expect("JWK, Key Path, or SSH Agent option is required.");
            LinkedDataProofs::sign(document, &options, &jwk).await?
        }
    };

    Ok(proof)
}
