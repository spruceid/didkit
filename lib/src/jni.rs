use std::ptr;

use async_std::task::block_on;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

use crate::error::Error;
use crate::LinkedDataProofOptions;
use crate::VerifiableCredential;
use crate::VerifiablePresentation;
use crate::JWK;

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

fn key_to_did(env: &JNIEnv, key_jstring: JString) -> Result<jstring, Error> {
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let key: JWK = serde_json::from_str(&key_json)?;
    let did = key.to_did()?;
    Ok(env.new_string(did).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_keyToDID(
    env: JNIEnv,
    _class: JClass,
    jwk: JString,
) -> jstring {
    jstring_or_error(&env, key_to_did(&env, jwk))
}

fn key_to_verification_method(env: &JNIEnv, key_jstring: JString) -> Result<jstring, Error> {
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let key: JWK = serde_json::from_str(&key_json)?;
    let verification_method = key.to_verification_method()?;
    Ok(env.new_string(verification_method).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_keyToVerificationMethod(
    env: JNIEnv,
    _class: JClass,
    jwk: JString,
) -> jstring {
    jstring_or_error(&env, key_to_verification_method(&env, jwk))
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
    let proof = block_on(credential.generate_proof(&key, &options))?;
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
    let result = block_on(vc.verify(Some(options)));
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
    let proof = block_on(presentation.generate_proof(&key, &options))?;
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
    let result = block_on(vp.verify(Some(options)));
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
