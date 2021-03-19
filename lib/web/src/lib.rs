use core::future::Future;

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use didkit::error::Error;
#[cfg(doc)]
use didkit::error::{didkit_error_code, didkit_error_message};
use didkit::get_verification_method;
use didkit::LinkedDataProofOptions;
use didkit::ProofPreparation;
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

async fn resolve_did(did: String, input_metadata: String) -> Result<String, String> {
    let (res_meta, doc, _) = DID_METHODS
        .to_resolver()
        .resolve(
            &did,
            &serde_json::from_str(&input_metadata).or_else(|e| Err(e.to_string()))?,
        )
        .await;

    if let Some(error) = res_meta.error {
        return Err(error);
    }

    if let Some(d) = doc {
        Ok(serde_json::to_string(&d).or_else(|e| Err(e.to_string()))?)
    } else {
        Err("No document resolved.".to_string())
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn resolveDID(did: String, input_metadata: String) -> Promise {
    future_to_promise(async {
        match resolve_did(did, input_metadata).await {
            Ok(string) => Ok(string.into()),
            Err(err) => Err(err.into()),
        }
    })
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

fn key_to_did(method_pattern: String, jwk: String) -> Result<String, Error> {
    let key: JWK = serde_json::from_str(&jwk)?;
    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(&key, &method_pattern))
        .ok_or(Error::UnableToGenerateDID)?;
    Ok(did)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn keyToDID(method_pattern: String, jwk: String) -> Result<String, JsValue> {
    map_jsvalue(key_to_did(method_pattern, jwk))
}

async fn key_to_verification_method(method_pattern: String, jwk: String) -> Result<String, Error> {
    let key: JWK = serde_json::from_str(&jwk)?;
    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(&key, &method_pattern))
        .ok_or(Error::UnableToGenerateDID)?;
    let did_resolver = DID_METHODS.to_resolver();
    let vm = get_verification_method(&did, did_resolver)
        .await
        .ok_or(Error::UnableToGetVerificationMethod)?;
    Ok(vm)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn keyToVerificationMethod(method_pattern: String, jwk: String) -> Promise {
    map_async_jsvalue(key_to_verification_method(method_pattern, jwk))
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

async fn prepare_issue_credential(
    credential: String,
    linked_data_proof_options: String,
    public_key: String,
) -> Result<String, Error> {
    let public_key: JWK = serde_json::from_str(&public_key)?;
    let credential = VerifiableCredential::from_json_unsigned(&credential)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let preparation = credential.prepare_proof(&public_key, &options).await?;
    let preparation_json = serde_json::to_string(&preparation)?;
    Ok(preparation_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(feature = "issue")]
pub fn prepareIssueCredential(
    credential: String,
    linked_data_proof_options: String,
    public_key: String,
) -> Promise {
    map_async_jsvalue(prepare_issue_credential(
        credential,
        linked_data_proof_options,
        public_key,
    ))
}

async fn complete_issue_credential(
    credential: String,
    preparation: String,
    signature: String,
) -> Result<String, Error> {
    let mut credential = VerifiableCredential::from_json_unsigned(&credential)?;
    let preparation: ProofPreparation = serde_json::from_str(&preparation)?;
    let proof = preparation.complete(&signature).await?;
    credential.add_proof(proof);
    let vc_json = serde_json::to_string(&credential)?;
    Ok(vc_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(feature = "issue")]
pub fn completeIssueCredential(
    credential: String,
    preparation: String,
    signature: String,
) -> Promise {
    map_async_jsvalue(complete_issue_credential(
        credential,
        preparation,
        signature,
    ))
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

#[cfg(any(
    all(feature = "issue", feature = "presentation"),
    all(feature = "issue", not(feature = "credential")),
    all(
        feature = "presentation",
        not(feature = "issue"),
        not(feature = "verify")
    )
))]
async fn did_auth(
    holder: String,
    linked_data_proof_options: String,
    key: String,
) -> Result<String, Error> {
    let mut presentation = VerifiablePresentation::default();
    presentation.holder = Some(ssi::vc::URI::String(holder));
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
pub fn DIDAuth(holder: String, linked_data_proof_options: String, key: String) -> Promise {
    map_async_jsvalue(did_auth(holder, linked_data_proof_options, key))
}
