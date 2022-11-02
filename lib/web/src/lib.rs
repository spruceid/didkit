use core::future::Future;
use std::convert::TryFrom;

use didkit::ssi::jwk::Params;
use js_sys::Promise;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use didkit::error::Error;
#[cfg(doc)]
use didkit::error::{didkit_error_code, didkit_error_message};
use didkit::get_verification_method;
use didkit::ssi::jwk::Algorithm;
use didkit::ssi::{self, ldp::ProofSuite};
use didkit::LinkedDataProofOptions;
use didkit::ProofPreparation;
use didkit::Source;
use didkit::VerifiableCredential;
use didkit::VerifiablePresentation;
use didkit::DID_METHODS;
use didkit::JWK;
use didkit::{Delegation, Invocation};
use didkit::{JWTOrLDPOptions, ProofFormat, URI};

pub static VERSION: &str = env!("CARGO_PKG_VERSION");

fn map_jsvalue(result: Result<String, Error>) -> Result<String, JsValue> {
    match result {
        Ok(string) => Ok(string),
        Err(err) => Err(err.to_string().into()),
    }
}

fn map_async_jsvalue<E: std::error::Error>(
    future: impl Future<Output = Result<String, E>> + 'static,
) -> Promise {
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

fn pubkey_to_did(method_pattern: String, pubkey_str: String) -> Result<String, Error> {
    let pubkey_bytes = didkit::util::decode_hex(&pubkey_str)?;
    let pubkey =
        k256::PublicKey::from_sec1_bytes(&pubkey_bytes).map_err(|e| Error::JWK(e.into()))?;
    let ec_params = ssi::jwk::ECParams::try_from(&pubkey).map_err(|e| Error::JWK(e))?;
    let jwk = JWK::from(Params::EC(ec_params));
    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(&jwk, &method_pattern))
        .ok_or(Error::UnableToGenerateDID)?;
    Ok(did)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn pubkeyToDID(method_pattern: String, pubkey_hex: String) -> Result<String, JsValue> {
    map_jsvalue(pubkey_to_did(method_pattern, pubkey_hex))
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
pub fn didToVerificationMethod(did: String) -> Promise {
    map_async_jsvalue(did_to_verification_method(did))
}

async fn did_to_verification_method(did: String) -> Result<String, Error> {
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

fn get_key_id(jwk: String, verification_method: Option<String>) -> Result<String, Error> {
    let key: JWK = serde_json::from_str(&jwk)?;
    // Ensure consistency between key ID and verification method URI.
    match (key.key_id.clone(), verification_method) {
        (Some(jwk_kid), None) => Ok(jwk_kid),
        (None, Some(vm_id)) => Ok(vm_id.to_string()),
        (None, None) => Ok("".to_string()),
        (Some(jwk_kid), Some(vm_id)) if jwk_kid == vm_id.to_string() => Ok(vm_id.to_string()),
        (Some(jwk_kid), Some(vm_id)) => Err(Error::VC(ssi::vc::Error::KeyIdVMMismatch(
            vm_id.to_string(),
            jwk_kid,
        ))),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn getKeyId(jwk: String, verification_method: Option<String>) -> Result<String, JsValue> {
    map_jsvalue(get_key_id(jwk, verification_method))
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
    proof_options: String,
    key: String,
) -> Result<String, Error> {
    let mut credential = VerifiableCredential::from_json_unsigned(&credential)?;
    let key: JWK = serde_json::from_str(&key)?;
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let vc_string = match proof_format {
        ProofFormat::JWT => {
            let vc_jwt = credential
                .generate_jwt(Some(&key), &options.ldp_options, resolver)
                .await?;
            vc_jwt
        }
        ProofFormat::LDP => {
            let proof = credential
                .generate_proof(&key, &options.ldp_options, resolver, &mut context_loader)
                .await?;
            credential.add_proof(proof);
            let vc_json = serde_json::to_string(&credential)?;
            vc_json
        }
        _ => Err(Error::UnknownProofFormat(proof_format.to_string()))?,
    };
    Ok(vc_string)
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
fn generate_credential_data_to_sign(
    credential: String,
    proof_options: String,
    algorithm: String,
    key_id: String,
) -> Result<String, Error> {
    let credential = VerifiableCredential::from_json_unsigned(&credential)?;
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let algorithm = match algorithm.as_str() {
        "ES256K" => Algorithm::ES256K,
        _ => return Err(Error::JWK(ssi::jwk::Error::UnsupportedKeyType)),
    };
    let key_id = if key_id.is_empty() {
        None
    } else {
        Some(key_id)
    };
    let vc_string = match proof_format {
        ProofFormat::JWT => {
            let vc_jwt =
                credential.generate_jwt_sign_data(&options.ldp_options, algorithm, key_id)?;
            vc_jwt
        }
        _ => Err(Error::UnknownProofFormat(proof_format.to_string()))?,
    };
    Ok(vc_string)
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
pub fn generateCredentialDataToSign(
    credential: String,
    proof_options: String,
    algorithm: String,
    key_id: String,
) -> Result<String, JsValue> {
    map_jsvalue(generate_credential_data_to_sign(
        credential,
        proof_options,
        algorithm,
        key_id,
    ))
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
pub fn finalizeCredential(signing_input: String, signature: String) -> Result<String, JsValue> {
    map_jsvalue(finalize_credential(signing_input, signature))
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
fn finalize_credential(signing_input: String, signature: String) -> Result<String, Error> {
    let sig_bytes = didkit::util::decode_hex(&signature)?;
    let sig_b64 = base64::encode_config(sig_bytes, base64::URL_SAFE_NO_PAD);
    let jws = signing_input.to_string() + "." + &sig_b64;
    Ok(jws)
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
pub fn issueCredential(credential: String, proof_options: String, key: String) -> Promise {
    map_async_jsvalue(issue_credential(credential, proof_options, key))
}

async fn prepare_issue_credential(
    credential: String,
    linked_data_proof_options: String,
    public_key: String,
) -> Result<String, Error> {
    let public_key: JWK = serde_json::from_str(&public_key)?;
    let credential = VerifiableCredential::from_json_unsigned(&credential)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let preparation = credential
        .prepare_proof(&public_key, &options, resolver, &mut context_loader)
        .await?;
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
    let proof = preparation
        .proof
        .type_
        .complete(&preparation, &signature)
        .await?;
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
async fn verify_credential(vc_string: String, proof_options: String) -> Result<String, Error> {
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let result = match proof_format {
        ProofFormat::JWT => {
            VerifiableCredential::verify_jwt(
                &vc_string,
                Some(options.ldp_options),
                resolver,
                &mut context_loader,
            )
            .await
        }
        ProofFormat::LDP => {
            let vc = VerifiableCredential::from_json_unsigned(&vc_string)?;
            vc.verify(Some(options.ldp_options), resolver, &mut context_loader)
                .await
        }
        _ => Err(Error::UnknownProofFormat(proof_format.to_string()))?,
    };
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
pub fn verifyCredential(vc: String, proof_options: String) -> Promise {
    map_async_jsvalue(verify_credential(vc, proof_options))
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
    proof_options: String,
    key: String,
) -> Result<String, Error> {
    let mut presentation = VerifiablePresentation::from_json_unsigned(&presentation)?;
    let key: JWK = serde_json::from_str(&key)?;
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let vp_string = match proof_format {
        ProofFormat::JWT => {
            presentation
                .generate_jwt(Some(&key), &options.ldp_options, resolver)
                .await?
        }
        ProofFormat::LDP => {
            let proof = presentation
                .generate_proof(&key, &options.ldp_options, resolver, &mut context_loader)
                .await?;
            presentation.add_proof(proof);
            serde_json::to_string(&presentation)?
        }
        _ => Err(Error::UnknownProofFormat(proof_format.to_string()))?,
    };
    Ok(vp_string)
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
pub fn issuePresentation(presentation: String, proof_options: String, key: String) -> Promise {
    map_async_jsvalue(issue_presentation(presentation, proof_options, key))
}

async fn prepare_issue_presentation(
    presentation: String,
    linked_data_proof_options: String,
    public_key: String,
) -> Result<String, Error> {
    let public_key: JWK = serde_json::from_str(&public_key)?;
    let presentation = VerifiablePresentation::from_json_unsigned(&presentation)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let preparation = presentation
        .prepare_proof(&public_key, &options, resolver, &mut context_loader)
        .await?;
    let preparation_json = serde_json::to_string(&preparation)?;
    Ok(preparation_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(feature = "issue")]
pub fn prepareIssuePresentation(
    presentation: String,
    linked_data_proof_options: String,
    public_key: String,
) -> Promise {
    map_async_jsvalue(prepare_issue_presentation(
        presentation,
        linked_data_proof_options,
        public_key,
    ))
}

async fn complete_issue_presentation(
    presentation: String,
    preparation: String,
    signature: String,
) -> Result<String, Error> {
    let mut presentation = VerifiablePresentation::from_json_unsigned(&presentation)?;
    let preparation: ProofPreparation = serde_json::from_str(&preparation)?;
    let proof = preparation
        .proof
        .type_
        .complete(&preparation, &signature)
        .await?;
    presentation.add_proof(proof);
    let vc_json = serde_json::to_string(&presentation)?;
    Ok(vc_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(feature = "issue")]
pub fn completeIssuePresentation(
    presentation: String,
    preparation: String,
    signature: String,
) -> Promise {
    map_async_jsvalue(complete_issue_presentation(
        presentation,
        preparation,
        signature,
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
async fn verify_presentation(vp_string: String, proof_options: String) -> Result<String, Error> {
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let result = match proof_format {
        ProofFormat::JWT => {
            VerifiablePresentation::verify_jwt(
                &vp_string,
                Some(options.ldp_options),
                resolver,
                &mut context_loader,
            )
            .await
        }
        ProofFormat::LDP => {
            let vp = VerifiablePresentation::from_json_unsigned(&vp_string)?;
            vp.verify(Some(options.ldp_options), resolver, &mut context_loader)
                .await
        }
        _ => Err(Error::UnknownProofFormat(proof_format.to_string()))?,
    };
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
pub fn verifyPresentation(vp: String, proof_options: String) -> Promise {
    map_async_jsvalue(verify_presentation(vp, proof_options))
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
async fn did_auth(holder: String, proof_options: String, key: String) -> Result<String, Error> {
    let mut presentation = VerifiablePresentation::default();
    presentation.holder = Some(ssi::vc::URI::String(holder));
    let key: JWK = serde_json::from_str(&key)?;
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let vp_string = match proof_format {
        ProofFormat::JWT => {
            presentation
                .generate_jwt(Some(&key), &options.ldp_options, resolver)
                .await?
        }
        ProofFormat::LDP => {
            let proof = presentation
                .generate_proof(&key, &options.ldp_options, resolver, &mut context_loader)
                .await?;
            presentation.add_proof(proof);
            serde_json::to_string(&presentation)?
        }
        _ => Err(Error::UnknownProofFormat(proof_format.to_string()))?,
    };
    Ok(vp_string)
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

#[derive(thiserror::Error, Debug)]
pub enum TezosJwkError {
    #[error(transparent)]
    TzKey(#[from] ssi::tzkey::DecodeTezosPkError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

async fn jwk_from_tezos(tz_pk: String) -> Result<String, TezosJwkError> {
    let jwk = ssi::tzkey::jwk_from_tezos_key(&tz_pk)?;
    let jwk_json = serde_json::to_string(&jwk)?;
    Ok(jwk_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn JWKFromTezos(tz: String) -> Promise {
    map_async_jsvalue(jwk_from_tezos(tz))
}

#[cfg(any(feature = "delegate", feature = "zcap"))]
async fn delegate_capability(
    capability: String,
    linked_data_proof_options: String,
    parent_caps: String,
    key: String,
) -> Result<String, Error> {
    let delegation: Delegation<Value, Value> = serde_json::from_str(&capability)?;
    let key: JWK = serde_json::from_str(&key)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let parents: Vec<String> = serde_json::from_str(&parent_caps)?;
    let proof = delegation
        .generate_proof(
            &key,
            &options,
            resolver,
            &mut context_loader,
            &parents.iter().map(|p| p.as_ref()).collect::<Vec<&str>>(),
        )
        .await?;
    let json = serde_json::to_string(&delegation.set_proof(proof))?;
    Ok(json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(feature = "delegate", feature = "zcap"))]
pub fn delegateCapability(
    capability: String,
    linked_data_proof_options: String,
    parents: String,
    key: String,
) -> Promise {
    map_async_jsvalue(delegate_capability(
        capability,
        linked_data_proof_options,
        parents,
        key,
    ))
}

async fn prepare_delegate_capability(
    capability: String,
    linked_data_proof_options: String,
    parent_caps: String,
    public_key: String,
) -> Result<String, Error> {
    let public_key: JWK = serde_json::from_str(&public_key)?;
    let capability: Delegation<Value, Value> = serde_json::from_str(&capability)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let parents: Vec<String> = serde_json::from_str(&parent_caps)?;
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let preparation = capability
        .prepare_proof(
            &public_key,
            &options,
            resolver,
            &mut context_loader,
            &parents.iter().map(|p| p.as_ref()).collect::<Vec<&str>>(),
        )
        .await?;
    let preparation_json = serde_json::to_string(&preparation)?;
    Ok(preparation_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(feature = "delegate", feature = "zcap"))]
pub fn prepareDelegateCapability(
    capability: String,
    linked_data_proof_options: String,
    parents: String,
    public_key: String,
) -> Promise {
    map_async_jsvalue(prepare_delegate_capability(
        capability,
        linked_data_proof_options,
        parents,
        public_key,
    ))
}

async fn complete_delegate_capability(
    capability: String,
    preparation: String,
    signature: String,
) -> Result<String, Error> {
    let capability: Delegation<Value, Value> = serde_json::from_str(&capability)?;
    let preparation: ProofPreparation = serde_json::from_str(&preparation)?;
    let proof = preparation
        .proof
        .type_
        .complete(&preparation, &signature)
        .await?;
    let json = serde_json::to_string(&capability.set_proof(proof))?;
    Ok(json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(feature = "delegate", feature = "zcap"))]
pub fn completeDelegateCapability(
    capability: String,
    preparation: String,
    signature: String,
) -> Promise {
    map_async_jsvalue(complete_delegate_capability(
        capability,
        preparation,
        signature,
    ))
}

#[cfg(any(feature = "delegate", feature = "zcap", feature = "invoke"))]
async fn verify_delegation(delegation: String) -> Result<String, Error> {
    let delegation: Delegation<Value, Value> = serde_json::from_str(&delegation)?;
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let result = delegation.verify(None, resolver, &mut context_loader).await;
    let result_json = serde_json::to_string(&result)?;
    Ok(result_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(feature = "delegate", feature = "zcap", feature = "invoke"))]
pub fn verifyDelegation(delegation: String) -> Promise {
    map_async_jsvalue(verify_delegation(delegation))
}

#[cfg(any(feature = "invoke", feature = "zcap"))]
async fn invoke_capability(
    invocation: String,
    target_id: String,
    linked_data_proof_options: String,
    key: String,
) -> Result<String, Error> {
    let invocation: Invocation<Value> = serde_json::from_str(&invocation)?;
    let key: JWK = serde_json::from_str(&key)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let proof = invocation
        .generate_proof(
            &key,
            &options,
            resolver,
            &mut context_loader,
            &URI::String(target_id),
        )
        .await?;
    let json = serde_json::to_string(&invocation.set_proof(proof))?;
    Ok(json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(feature = "invoke", feature = "zcap"))]
pub fn invokeCapability(
    invocation: String,
    target_id: String,
    linked_data_proof_options: String,
    key: String,
) -> Promise {
    map_async_jsvalue(invoke_capability(
        invocation,
        target_id,
        linked_data_proof_options,
        key,
    ))
}

async fn prepare_invoke_capability(
    invocation: String,
    target_id: String,
    linked_data_proof_options: String,
    public_key: String,
) -> Result<String, Error> {
    let public_key: JWK = serde_json::from_str(&public_key)?;
    let invocation: Invocation<Value> = serde_json::from_str(&invocation)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options)?;
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let preparation = invocation
        .prepare_proof(
            &public_key,
            &options,
            resolver,
            &mut context_loader,
            &URI::String(target_id),
        )
        .await?;
    let preparation_json = serde_json::to_string(&preparation)?;
    Ok(preparation_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(feature = "invoke", feature = "zcap"))]
pub fn prepareInvokeCapability(
    invocation: String,
    target_id: String,
    linked_data_proof_options: String,
    public_key: String,
) -> Promise {
    map_async_jsvalue(prepare_invoke_capability(
        invocation,
        target_id,
        linked_data_proof_options,
        public_key,
    ))
}

async fn complete_invoke_capability(
    invocation: String,
    preparation: String,
    signature: String,
) -> Result<String, Error> {
    let invocation: Invocation<Value> = serde_json::from_str(&invocation)?;
    let preparation: ProofPreparation = serde_json::from_str(&preparation)?;
    let proof = preparation
        .proof
        .type_
        .complete(&preparation, &signature)
        .await?;
    let json = serde_json::to_string(&invocation.set_proof(proof))?;
    Ok(json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(feature = "invoke", feature = "zcap"))]
pub fn completeInvokeCapability(
    invocation: String,
    preparation: String,
    signature: String,
) -> Promise {
    map_async_jsvalue(complete_invoke_capability(
        invocation,
        preparation,
        signature,
    ))
}

#[cfg(any(feature = "invoke", feature = "zcap"))]
async fn verify_invocation_signature(invocation: String) -> Result<String, Error> {
    let invocation: Invocation<Value> = serde_json::from_str(&invocation)?;
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let result = invocation
        .verify_signature(None, resolver, &mut context_loader)
        .await;
    let result_json = serde_json::to_string(&result)?;
    Ok(result_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(feature = "invoke", feature = "zcap"))]
pub fn verifyInvocationSignature(invocation: String) -> Promise {
    map_async_jsvalue(verify_invocation_signature(invocation))
}

#[cfg(any(feature = "invoke", feature = "zcap"))]
async fn verify_invocation(invocation: String, delegation: String) -> Result<String, Error> {
    let invocation: Invocation<Value> = serde_json::from_str(&invocation)?;
    let delegation: Delegation<Value, Value> = serde_json::from_str(&delegation)?;
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let result = invocation
        .verify(None, resolver, &mut context_loader, &delegation)
        .await;
    let result_json = serde_json::to_string(&result)?;
    Ok(result_json)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(any(feature = "invoke", feature = "zcap"))]
pub fn verifyInvocation(invocation: String, delegation: String) -> Promise {
    map_async_jsvalue(verify_invocation(invocation, delegation))
}

#[cfg(test)]
mod tests {
    use didkit::{util::encode_hex, VerificationResult};

    use super::*;
    #[tokio::test]
    async fn issue_credential_verify_test() {
        let m_key = r#"{"kty":"EC","crv":"secp256k1","x":"xna2cOr1YoelW64E85cQQ1EzPxO2BSVIBl2Ub53C8FI","y":"levEBIFG6eTPIWzb7YQ30P0Ypp9yK-NRMnCaOKdWMME","d":"kQ5inxC_5p_HD8Y7e8bMLWudSvIvzSd2luB85MuTbmE"}"#.to_string();
        let m_did = key_to_did("key".to_string(), m_key.clone()).unwrap();
        let verification_method = key_to_verification_method("key".to_string(), m_key.clone())
            .await
            .unwrap();

        let key = r#"{"kty":"EC","crv":"secp256k1","x":"X7ZzK9t8i6LZgi7lcKGXLMzeV9PLH2NIPNip_g_8eso","y":"cqZciccFbybaKHxKMm8em48rSH26Cm0peOvNwvelVgM","d":"NSf9zygkwE2UoJMlzs-nf0UnIYju_d_cVG2we1EKZOQ"}"#.to_string();
        let did = key_to_did("key".to_string(), key.clone()).unwrap();
        let proof_options = format!(
            r#"{{
            "proofPurpose": "assertionMethod",
            "proofFormat": "jwt",
            "verificationMethod": "{}"
          }}"#,
            verification_method
        );
        let credential = issue_credential(
            format!(
                r#"
        {{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "{}",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {{"id":"{}"}}
        }}
        "#,
                m_did.clone(),
                did
            ),
            proof_options.clone(),
            m_key,
        )
        .await
        .unwrap();
        println!("{}", credential);

        let res = verify_credential(credential, proof_options).await.unwrap();
        println!("{}", res);
    }

    #[tokio::test]
    async fn external_sign_verify_test() {
        let m_key = r#"{"kty":"EC","crv":"secp256k1","x":"xna2cOr1YoelW64E85cQQ1EzPxO2BSVIBl2Ub53C8FI","y":"levEBIFG6eTPIWzb7YQ30P0Ypp9yK-NRMnCaOKdWMME","d":"kQ5inxC_5p_HD8Y7e8bMLWudSvIvzSd2luB85MuTbmE"}"#.to_string();
        let m_did = key_to_did("key".to_string(), m_key.clone()).unwrap();
        let verification_method = key_to_verification_method("key".to_string(), m_key.clone())
            .await
            .unwrap();

        let key = r#"{"kty":"EC","crv":"secp256k1","x":"X7ZzK9t8i6LZgi7lcKGXLMzeV9PLH2NIPNip_g_8eso","y":"cqZciccFbybaKHxKMm8em48rSH26Cm0peOvNwvelVgM","d":"NSf9zygkwE2UoJMlzs-nf0UnIYju_d_cVG2we1EKZOQ"}"#.to_string();
        let did = key_to_did("key".to_string(), key.clone()).unwrap();

        let proof_options = format!(
            r#"{{
            "proofPurpose": "assertionMethod",
            "proofFormat": "jwt",
            "verificationMethod": "{}"
          }}"#,
            verification_method
        );
        let proof_options_verif = r#"{
            "proofPurpose": "assertionMethod",
            "proofFormat": "jwt"
          }"#
        .to_string();

        let data_to_sign = generate_credential_data_to_sign(
            format!(
                r#"
        {{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "{}",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {{"id":"{}"}}
        }}
        "#,
                m_did.clone(),
                did
            ),
            proof_options.clone(),
            "ES256K".to_string(),
            verification_method,
        )
        .unwrap();

        let signature = {
            let key: JWK = serde_json::from_str(&m_key.clone()).unwrap();
            ssi::jws::sign_bytes(Algorithm::ES256K, data_to_sign.as_bytes(), &key).unwrap()
        };

        let sig_string = didkit::util::encode_hex(&signature);

        let credential = finalize_credential(data_to_sign, sig_string).unwrap();

        let res = verify_credential(credential, proof_options_verif)
            .await
            .unwrap();
        let verif_result: VerificationResult = serde_json::from_str(&res).unwrap();

        assert!(verif_result.errors.is_empty());
    }
}
