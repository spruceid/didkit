#[cfg(not(feature = "wasm"))]
pub mod c;
mod did_methods;
pub mod error;
#[cfg(not(feature = "wasm"))]
pub mod jni;

#[macro_use]
extern crate lazy_static;

pub use crate::did_methods::DID_METHODS;
pub use crate::error::Error;
pub use ssi::did::DIDMethod;
pub use ssi::did::Source;
pub use ssi::did_resolve::DIDResolver;
pub use ssi::jwk::JWK;
pub use ssi::ldp::resolve_key;
pub use ssi::vc::get_verification_method;
pub use ssi::vc::Credential as VerifiableCredential;
pub use ssi::vc::LinkedDataProofOptions;
pub use ssi::vc::Presentation as VerifiablePresentation;
pub use ssi::vc::ProofPurpose;
pub use ssi::vc::VerificationResult;
