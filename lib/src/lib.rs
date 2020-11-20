pub mod c;
pub mod error;
pub mod jni;

pub use ssi::error::Error;
pub use ssi::jwk::JWK;
pub use ssi::vc::Credential as VerifiableCredential;
pub use ssi::vc::LinkedDataProofOptions;
pub use ssi::vc::Presentation as VerifiablePresentation;
pub use ssi::vc::ProofPurpose;
pub use ssi::vc::VerificationResult;
