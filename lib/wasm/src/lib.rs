use core::future::Future;

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use didkit::error::Error;
#[cfg(doc)]
use didkit::error::{didkit_error_code, didkit_error_message};
use didkit::get_verification_method;
use didkit::LinkedDataProofOptions;
use didkit::Source;
use didkit::VerifiableCredential;
use didkit::VerifiablePresentation;
use didkit::DID_METHODS;
use didkit::JWK;

pub static VERSION: &str = env!("CARGO_PKG_VERSION");

fn map_jsvalue(result: Result<String, Error>) -> Result<String, JsValue> {
    match result {
        Ok(string) => Ok(string),
        Err(err) => Err(err.to_string().into()),
    }
}

fn map_async_jsvalue(future: impl Future<Output = Result<String, Error>> + 'static) -> Promise {
    future_to_promise(async {
        match future.await {
            Ok(string) => Ok(string.into()),
            Err(err) => Err(err.to_string().into()),
        }
    })
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn getVersion() -> String {
    VERSION.into()
}

#[cfg(feature = "generate")]
fn generate_ed25519_key() -> Result<String, Error> {
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

fn key_to_did(method_name: String, jwk: String) -> Result<String, Error> {
    let key: JWK = serde_json::from_str(&jwk)?;
    let did_method = DID_METHODS
        .get(&method_name)
        .ok_or(Error::UnknownDIDMethod)?;
    let did = did_method
        .generate(&Source::Key(&key))
        .ok_or(Error::UnableToGenerateDID)?;
    Ok(did)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn keyToDID(method_name: String, jwk: String) -> Result<String, JsValue> {
    map_jsvalue(key_to_did(method_name, jwk))
}

async fn key_to_verification_method(method_name: String, jwk: String) -> Result<String, Error> {
    let key: JWK = serde_json::from_str(&jwk)?;
    let did_method = DID_METHODS
        .get(&method_name)
        .ok_or(Error::UnknownDIDMethod)?;
    let did = did_method
        .generate(&Source::Key(&key))
        .ok_or(Error::UnableToGenerateDID)?;
    let did_resolver = did_method.to_resolver();
    let vm = get_verification_method(&did, did_resolver)
        .await
        .ok_or(Error::UnableToGetVerificationMethod)?;
    Ok(vm)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn keyToVerificationMethod(method_name: String, jwk: String) -> Promise {
    map_async_jsvalue(key_to_verification_method(method_name, jwk))
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
async fn issue_credential(
    credential: String,
    linked_data_proof_options: String,
    key: String,
) -> Result<String, Error> {
    let mut credential = VerifiableCredential::from_json_unsigned(&credential)?;
    let key: JWK = serde_json::from_str(&key)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let proof = credential.generate_proof(&key, &options).await?;
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
) -> Promise {
    map_async_jsvalue(issue_credential(credential, linked_data_proof_options, key))
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
async fn verify_credential(vc: String, linked_data_proof_options: String) -> Result<String, Error> {
    let vc = VerifiableCredential::from_json_unsigned(&vc)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let result = vc.verify(Some(options), DID_METHODS.to_resolver()).await;
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
pub fn verifyCredential(vc: String, linked_data_proof_options: String) -> Promise {
    map_async_jsvalue(verify_credential(vc, linked_data_proof_options))
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
async fn issue_presentation(
    presentation: String,
    linked_data_proof_options: String,
    key: String,
) -> Result<String, Error> {
    let mut presentation = VerifiablePresentation::from_json_unsigned(&presentation)?;
    let key: JWK = serde_json::from_str(&key)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let proof = presentation.generate_proof(&key, &options).await?;
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
) -> Promise {
    map_async_jsvalue(issue_presentation(
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
async fn verify_presentation(
    vp: String,
    linked_data_proof_options: String,
) -> Result<String, Error> {
    let vp = VerifiablePresentation::from_json_unsigned(&vp)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let result = vp.verify(Some(options), DID_METHODS.to_resolver()).await;
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
pub fn verifyPresentation(vp: String, linked_data_proof_options: String) -> Promise {
    map_async_jsvalue(verify_presentation(vp, linked_data_proof_options))
}
