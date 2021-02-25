use std::ptr;

use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

use crate::error::Error;
use crate::get_verification_method;
use crate::runtime;
use crate::LinkedDataProofOptions;
use crate::ResolutionResult;
use crate::Source;
use crate::VerifiableCredential;
use crate::VerifiablePresentation;
use crate::DID_METHODS;
use crate::JWK;
use crate::{dereference, DereferencingInputMetadata, ResolutionInputMetadata};

pub static VERSION: &str = env!("CARGO_PKG_VERSION");
pub static DIDKIT_EXCEPTION_CLASS: &str = "com/spruceid/DIDKitException";

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_getVersion(env: JNIEnv, _class: JClass) -> jstring {
    env.new_string(VERSION)
        .expect("Unable to create Java string")
        .into_inner()
}

fn jstring_or_error(env: &JNIEnv, result: Result<jstring, Error>) -> jstring {
    match result {
        Ok(jstring) => jstring,
        Err(err) => {
            // TODO: pass the error code into the constructor somehow
            env.throw_new(DIDKIT_EXCEPTION_CLASS, err.to_string())
                .unwrap();
            ptr::null_mut()
        }
    }
}

fn generate_ed25519_key(env: &JNIEnv) -> Result<jstring, Error> {
    let jwk = JWK::generate_ed25519()?;
    let jwk_json = serde_json::to_string(&jwk)?;
    Ok(env.new_string(jwk_json).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_generateEd25519Key(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    jstring_or_error(&env, generate_ed25519_key(&env))
}

fn key_to_did(
    env: &JNIEnv,
    method_name_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let method_name: String = env.get_string(method_name_jstring).unwrap().into();
    let key: JWK = serde_json::from_str(&key_json)?;
    let did_method = DID_METHODS
        .get(&method_name)
        .ok_or(Error::UnknownDIDMethod)?;
    let did = did_method
        .generate(&Source::Key(&key))
        .ok_or(Error::UnableToGenerateDID)?;
    Ok(env.new_string(did).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_keyToDID(
    env: JNIEnv,
    _class: JClass,
    method_name: JString,
    jwk: JString,
) -> jstring {
    jstring_or_error(&env, key_to_did(&env, method_name, jwk))
}

fn key_to_verification_method(
    env: &JNIEnv,
    method_name_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let method_name: String = env.get_string(method_name_jstring).unwrap().into();
    let key: JWK = serde_json::from_str(&key_json)?;
    let did_method = DID_METHODS
        .get(&method_name)
        .ok_or(Error::UnknownDIDMethod)?;
    let did = did_method
        .generate(&Source::Key(&key))
        .ok_or(Error::UnableToGenerateDID)?;
    let did_resolver = did_method.to_resolver();
    let rt = runtime::get()?;
    let verification_method = rt
        .block_on(get_verification_method(&did, did_resolver))
        .ok_or(Error::UnableToGetVerificationMethod)?;
    Ok(env.new_string(verification_method).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_keyToVerificationMethod(
    env: JNIEnv,
    _class: JClass,
    method_name: JString,
    jwk: JString,
) -> jstring {
    jstring_or_error(&env, key_to_verification_method(&env, method_name, jwk))
}

fn issue_credential(
    env: &JNIEnv,
    credential_jstring: JString,
    linked_data_proof_options_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let credential_json: String = env.get_string(credential_jstring).unwrap().into();
    let linked_data_proof_options_json: String = env
        .get_string(linked_data_proof_options_jstring)
        .unwrap()
        .into();
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let mut credential = VerifiableCredential::from_json_unsigned(&credential_json)?;
    let key: JWK = serde_json::from_str(&key_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options_json)?;
    let rt = runtime::get()?;
    let proof = rt.block_on(credential.generate_proof(&key, &options))?;
    credential.add_proof(proof);
    let vc_json = serde_json::to_string(&credential)?;
    Ok(env.new_string(vc_json).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_issueCredential(
    env: JNIEnv,
    _class: JClass,
    credential: JString,
    options: JString,
    key: JString,
) -> jstring {
    jstring_or_error(&env, issue_credential(&env, credential, options, key))
}

fn verify_credential(
    env: &JNIEnv,
    vc_jstring: JString,
    linked_data_proof_options_jstring: JString,
) -> Result<jstring, Error> {
    let vc_json: String = env.get_string(vc_jstring).unwrap().into();
    let linked_data_proof_options_json: String = env
        .get_string(linked_data_proof_options_jstring)
        .unwrap()
        .into();
    let vc = VerifiableCredential::from_json_unsigned(&vc_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options_json)?;
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let result = rt.block_on(vc.verify(Some(options), resolver));
    let result_json = serde_json::to_string(&result)?;
    Ok(env.new_string(result_json).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_verifyCredential(
    env: JNIEnv,
    _class: JClass,
    credential: JString,
    options: JString,
) -> jstring {
    jstring_or_error(&env, verify_credential(&env, credential, options))
}

fn issue_presentation(
    env: &JNIEnv,
    presentation_jstring: JString,
    linked_data_proof_options_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let presentation_json: String = env.get_string(presentation_jstring).unwrap().into();
    let linked_data_proof_options_json: String = env
        .get_string(linked_data_proof_options_jstring)
        .unwrap()
        .into();
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let mut presentation = VerifiablePresentation::from_json_unsigned(&presentation_json)?;
    let key: JWK = serde_json::from_str(&key_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options_json)?;
    let rt = runtime::get()?;
    let proof = rt.block_on(presentation.generate_proof(&key, &options))?;
    presentation.add_proof(proof);
    let vp_json = serde_json::to_string(&presentation)?;
    Ok(env.new_string(vp_json).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_issuePresentation(
    env: JNIEnv,
    _class: JClass,
    presentation: JString,
    options: JString,
    key: JString,
) -> jstring {
    jstring_or_error(&env, issue_presentation(&env, presentation, options, key))
}

fn did_auth(
    env: &JNIEnv,
    holder_jstring: JString,
    linked_data_proof_options_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let holder: String = env.get_string(holder_jstring).unwrap().into();
    let linked_data_proof_options_json: String = env
        .get_string(linked_data_proof_options_jstring)
        .unwrap()
        .into();
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let mut presentation = VerifiablePresentation::default();
    presentation.holder = Some(ssi::vc::URI::String(holder));
    let key: JWK = serde_json::from_str(&key_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options_json)?;
    let rt = runtime::get()?;
    let proof = rt.block_on(presentation.generate_proof(&key, &options))?;
    presentation.add_proof(proof);
    let vp_json = serde_json::to_string(&presentation)?;
    Ok(env.new_string(vp_json).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_DIDAuth(
    env: JNIEnv,
    _class: JClass,
    holder: JString,
    options: JString,
    key: JString,
) -> jstring {
    jstring_or_error(&env, did_auth(&env, holder, options, key))
}

fn verify_presentation(
    env: &JNIEnv,
    vp_jstring: JString,
    linked_data_proof_options_jstring: JString,
) -> Result<jstring, Error> {
    let vp_json: String = env.get_string(vp_jstring).unwrap().into();
    let linked_data_proof_options_json: String = env
        .get_string(linked_data_proof_options_jstring)
        .unwrap()
        .into();
    let vp = VerifiablePresentation::from_json_unsigned(&vp_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(&linked_data_proof_options_json)?;
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let result = rt.block_on(vp.verify(Some(options), resolver));
    let result_json = serde_json::to_string(&result)?;
    Ok(env.new_string(result_json).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_verifyPresentation(
    env: JNIEnv,
    _class: JClass,
    presentation: JString,
    options: JString,
) -> jstring {
    jstring_or_error(&env, verify_presentation(&env, presentation, options))
}

fn resolve_did(
    env: &JNIEnv,
    did_jstring: JString,
    input_metadata_jstring: JString,
) -> Result<jstring, Error> {
    let did: String = env.get_string(did_jstring).unwrap().into();
    let input_metadata_json: String = if input_metadata_jstring.is_null() {
        env.get_string(input_metadata_jstring).unwrap().into()
    } else {
        "{}".to_string()
    };
    let input_metadata: ResolutionInputMetadata = serde_json::from_str(&input_metadata_json)?;
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let (res_meta, doc_opt, doc_meta_opt) = rt.block_on(resolver.resolve(&did, &input_metadata));
    let result = ResolutionResult {
        did_document: doc_opt,
        did_resolution_metadata: Some(res_meta),
        did_document_metadata: doc_meta_opt,
        ..Default::default()
    };
    let result_json = serde_json::to_string(&result)?;
    Ok(env.new_string(result_json).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_resolveDID(
    env: JNIEnv,
    _class: JClass,
    did: JString,
    input_metadata: JString,
) -> jstring {
    jstring_or_error(&env, resolve_did(&env, did, input_metadata))
}

fn dereference_did_url(
    env: &JNIEnv,
    did_url_jstring: JString,
    input_metadata_jstring: JString,
) -> Result<jstring, Error> {
    let did_url: String = env.get_string(did_url_jstring).unwrap().into();
    let input_metadata_json: String = if input_metadata_jstring.is_null() {
        env.get_string(input_metadata_jstring).unwrap().into()
    } else {
        "{}".to_string()
    };
    let input_metadata: DereferencingInputMetadata = serde_json::from_str(&input_metadata_json)?;
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let deref_result = rt.block_on(dereference(resolver, &did_url, &input_metadata));
    let result_json = serde_json::to_string(&deref_result)?;
    Ok(env.new_string(result_json).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_dereferenceDIDURL(
    env: JNIEnv,
    _class: JClass,
    did_url: JString,
    input_metadata: JString,
) -> jstring {
    jstring_or_error(&env, dereference_did_url(&env, did_url, input_metadata))
}
