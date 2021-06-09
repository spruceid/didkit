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

pub fn generate_ed25519_key() -> Result<String, Error> {
    let jwk = JWK::generate_ed25519()?;
    let jwk_string = serde_json::to_string(&jwk)?;
    Ok(jwk_string)
}

pub fn key_to_did(method_pattern: &str, key_json: &str) -> Result<String, Error> {
    let key: JWK = serde_json::from_str(key_json)?;
    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(&key, method_pattern))
        .ok_or(Error::UnableToGenerateDID)?;
    Ok(did)
}

pub fn key_to_verification_method(method_pattern: &str, key_json: &str) -> Result<String, Error> {
    let key: JWK = serde_json::from_str(key_json)?;
    let did_method = DID_METHODS
        .get(&method_pattern)
        .ok_or(Error::UnknownDIDMethod)?;
    let did = did_method
        .generate(&Source::Key(&key))
        .ok_or(Error::UnableToGenerateDID)?;
    let did_resolver = did_method.to_resolver();
    let rt = runtime::get()?;
    let vm = rt
        .block_on(get_verification_method(&did, did_resolver))
        .ok_or(Error::UnableToGetVerificationMethod)?;
    Ok(vm)
}

pub fn resolve_did(did: &str, input_metadata_json: &str) -> Result<String, Error> {
    let input_metadata: ResolutionInputMetadata = serde_json::from_str(input_metadata_json)?;
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let (res_meta, doc_opt, doc_meta_opt) = rt.block_on(resolver.resolve(did, &input_metadata));
    let result = ResolutionResult {
        did_document: doc_opt,
        did_resolution_metadata: Some(res_meta),
        did_document_metadata: doc_meta_opt,
        ..Default::default()
    };
    let result_string = serde_json::to_string(&result)?;
    Ok(result_string)
}

pub fn dereference_did_url(did_url: &str, input_metadata_json: &str) -> Result<String, Error> {
    let input_metadata: DereferencingInputMetadata = serde_json::from_str(input_metadata_json)?;
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let deref_result = rt.block_on(dereference(resolver, did_url, &input_metadata));
    let result = serde_json::json!(deref_result);
    let result_string = serde_json::to_string(&result)?;
    Ok(result_string)
}

pub fn issue_credential(
    credential_json: &str,
    proof_options_json: &str,
    key_json: &str,
) -> Result<String, Error> {
    let mut credential = VerifiableCredential::from_json_unsigned(credential_json)?;
    let key: JWK = serde_json::from_str(key_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(proof_options_json)?;
    let rt = runtime::get()?;
    let proof = rt.block_on(credential.generate_proof(&key, &options))?;
    credential.add_proof(proof);
    let vc_string = serde_json::to_string(&credential)?;
    Ok(vc_string)
}

pub fn verify_credential(vc_str: &str, proof_options_json: &str) -> Result<String, Error> {
    let options: LinkedDataProofOptions = serde_json::from_str(&proof_options_json)?;
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let vc = VerifiableCredential::from_json_unsigned(vc_str)?;
    let result = rt.block_on(vc.verify(Some(options), resolver));
    let result_json = serde_json::to_string(&result)?;
    Ok(result_json)
}

pub fn issue_presentation(
    presentation_json: &str,
    proof_options_json: &str,
    key_json: &str,
) -> Result<String, Error> {
    let mut presentation = VerifiablePresentation::from_json_unsigned(presentation_json)?;
    let key: JWK = serde_json::from_str(key_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(proof_options_json)?;
    let rt = runtime::get()?;
    let proof = rt.block_on(presentation.generate_proof(&key, &options))?;
    presentation.add_proof(proof);
    let vp_string = serde_json::to_string(&presentation)?;
    Ok(vp_string)
}

pub fn verify_presentation(vp_str: &str, proof_options_json: &str) -> Result<String, Error> {
    let options: LinkedDataProofOptions = serde_json::from_str(proof_options_json)?;
    let rt = runtime::get()?;
    let resolver = DID_METHODS.to_resolver();
    let vp = VerifiablePresentation::from_json_unsigned(vp_str)?;
    let result = rt.block_on(vp.verify(Some(options), resolver));
    let result_json = serde_json::to_string(&result)?;
    Ok(result_json)
}

pub fn did_auth(holder: &str, proof_options_json: &str, key_json: &str) -> Result<String, Error> {
    let mut presentation = VerifiablePresentation::default();
    presentation.holder = Some(ssi::vc::URI::String(holder.to_string()));
    let key: JWK = serde_json::from_str(key_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(proof_options_json)?;
    let rt = runtime::get()?;
    let proof = rt.block_on(presentation.generate_proof(&key, &options))?;
    presentation.add_proof(proof);
    let vp_string = serde_json::to_string(&presentation)?;
    Ok(vp_string)
}
