#[cfg(not(feature = "wasm"))]
pub mod c;
mod did_methods;
pub mod error;
#[cfg(not(feature = "wasm"))]
pub mod jni;
#[cfg(not(feature = "wasm"))]
pub mod runtime;

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
pub use ssi::vc::LinkedDataProofOptions;
pub use ssi::vc::Presentation as VerifiablePresentation;
pub use ssi::vc::ProofPurpose;
pub use ssi::vc::VerificationResult;
