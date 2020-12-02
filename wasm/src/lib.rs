use wasm_bindgen::prelude::*;

use ssi::error::Error;
use ssi::jwk::JWK;
use ssi::vc::Credential as VerifiableCredential;
use ssi::vc::LinkedDataProofOptions;
use ssi::vc::Presentation as VerifiablePresentation;

pub static VERSION: &str = env!("CARGO_PKG_VERSION");

fn map_jsvalue(result: Result<String, Error>) -> Result<String, JsValue> {
    match result {
        Ok(string) => Ok(string),
        Err(err) => Err("an error occurred".into()),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn getVersion() -> String {
    VERSION.into()
}

#[cfg(feature = "generate")]
pub fn generate_ed25519_key() -> Result<String, Error> {
    let jwk = JWK::generate_ed25519()?;
    let jwk_json = serde_json::to_string(&jwk)?;
    Ok(jwk_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(feature = "generate")]
pub fn generateEd25519Key() -> Result<String, JsValue> {
    map_jsvalue(generate_ed25519_key())
}

pub fn key_to_did(jwk: String) -> Result<String, Error> {
    let key: JWK = serde_json::from_str(&jwk)?;
    let did = key.to_did()?;
    Ok(did)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn keyToDID(jwk: String) -> Result<String, JsValue> {
    map_jsvalue(key_to_did(jwk))
}

pub fn key_to_verification_method(jwk: String) -> Result<String, Error> {
    let key: JWK = serde_json::from_str(&jwk)?;
    let verification_method = key.to_verification_method()?;
    Ok(verification_method)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn keyToVerificationMethod(jwk: String) -> Result<String, JsValue> {
    map_jsvalue(key_to_verification_method(jwk))
}

#[cfg(any(
    all(feature = "issue", feature = "credential"),
    all(feature = "issue", not(feature = "presentation")),
    all(
        feature = "credential",
        not(feature = "issue"),
        not(feature = "verify")
    )
))]
fn issue_credential(
    credential: String,
    linked_data_proof_options: String,
    key: String,
) -> Result<String, Error> {
    let mut credential = VerifiableCredential::from_json_unsigned(&credential)?;
    let key: JWK = serde_json::from_str(&key)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let proof = credential.generate_proof(&key, &options)?;
    credential.add_proof(proof);
    let vc_json = serde_json::to_string(&credential)?;
    Ok(vc_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(
    all(feature = "issue", feature = "credential"),
    all(feature = "issue", not(feature = "presentation")),
    all(
        feature = "credential",
        not(feature = "issue"),
        not(feature = "verify")
    )
))]
pub fn issueCredential(
    credential: String,
    linked_data_proof_options: String,
    key: String,
) -> Result<String, JsValue> {
    map_jsvalue(issue_credential(credential, linked_data_proof_options, key))
}

#[cfg(any(
    all(feature = "verify", feature = "credential"),
    all(feature = "verify", not(feature = "presentation")),
    all(
        feature = "credential",
        not(feature = "issue"),
        not(feature = "verify")
    )
))]
fn verify_credential(vc: String, linked_data_proof_options: String) -> Result<String, Error> {
    let vc = VerifiableCredential::from_json_unsigned(&vc)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let result = vc.verify(Some(options));
    let result_json = serde_json::to_string(&result)?;
    Ok(result_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(
    all(feature = "verify", feature = "credential"),
    all(feature = "verify", not(feature = "presentation")),
    all(
        feature = "credential",
        not(feature = "issue"),
        not(feature = "verify")
    )
))]
pub fn verifyCredential(vc: String, linked_data_proof_options: String) -> Result<String, JsValue> {
    map_jsvalue(verify_credential(vc, linked_data_proof_options))
}

#[cfg(any(
    all(feature = "issue", feature = "presentation"),
    all(feature = "issue", not(feature = "credential")),
    all(
        feature = "presentation",
        not(feature = "issue"),
        not(feature = "verify")
    )
))]
fn issue_presentation(
    presentation: String,
    linked_data_proof_options: String,
    key: String,
) -> Result<String, Error> {
    let mut presentation = VerifiablePresentation::from_json_unsigned(&presentation)?;
    let key: JWK = serde_json::from_str(&key)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let proof = presentation.generate_proof(&key, &options)?;
    presentation.add_proof(proof);
    let vp_json = serde_json::to_string(&presentation)?;
    Ok(vp_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(
    all(feature = "issue", feature = "presentation"),
    all(feature = "issue", not(feature = "credential")),
    all(
        feature = "presentation",
        not(feature = "issue"),
        not(feature = "verify")
    )
))]
pub fn issuePresentation(
    presentation: String,
    linked_data_proof_options: String,
    key: String,
) -> Result<String, JsValue> {
    map_jsvalue(issue_presentation(
        presentation,
        linked_data_proof_options,
        key,
    ))
}

#[cfg(any(
    all(feature = "verify", feature = "presentation"),
    all(feature = "verify", not(feature = "credential")),
    all(
        feature = "presentation",
        not(feature = "issue"),
        not(feature = "verify")
    )
))]
fn verify_presentation(vp: String, linked_data_proof_options: String) -> Result<String, Error> {
    let vp = VerifiablePresentation::from_json_unsigned(&vp)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let result = vp.verify(Some(options));
    let result_json = serde_json::to_string(&result)?;
    Ok(result_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(
    all(feature = "verify", feature = "presentation"),
    all(feature = "verify", not(feature = "credential")),
    all(
        feature = "presentation",
        not(feature = "issue"),
        not(feature = "verify")
    )
))]
pub fn verifyPresentation(
    vp: String,
    linked_data_proof_options: String,
) -> Result<String, JsValue> {
    map_jsvalue(verify_presentation(vp, linked_data_proof_options))
}
