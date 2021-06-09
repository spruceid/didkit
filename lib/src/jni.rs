use std::ptr;

use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

use crate::error::Error;

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
    let jwk_string = crate::generate_ed25519_key()?;
    Ok(env.new_string(jwk_string).unwrap().into_inner())
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
    method_pattern_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let method_pattern: String = env.get_string(method_pattern_jstring).unwrap().into();
    let did = crate::key_to_did(&method_pattern, &key_json)?;
    Ok(env.new_string(did).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_keyToDID(
    env: JNIEnv,
    _class: JClass,
    method_pattern: JString,
    jwk: JString,
) -> jstring {
    jstring_or_error(&env, key_to_did(&env, method_pattern, jwk))
}

fn key_to_verification_method(
    env: &JNIEnv,
    method_pattern_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let method_pattern: String = env.get_string(method_pattern_jstring).unwrap().into();
    let vm = crate::key_to_verification_method(&method_pattern, &key_json)?;
    Ok(env.new_string(vm).unwrap().into_inner())
}

#[no_mangle]
pub extern "system" fn Java_com_spruceid_DIDKit_keyToVerificationMethod(
    env: JNIEnv,
    _class: JClass,
    method_pattern: JString,
    jwk: JString,
) -> jstring {
    jstring_or_error(&env, key_to_verification_method(&env, method_pattern, jwk))
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
    let vc_string =
        crate::issue_credential(&credential_json, &linked_data_proof_options_json, &key_json)?;
    Ok(env.new_string(vc_string).unwrap().into_inner())
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
    let result_json = crate::verify_credential(&vc_json, &linked_data_proof_options_json)?;
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
    let vp_string = crate::issue_presentation(
        &presentation_json,
        &linked_data_proof_options_json,
        &key_json,
    )?;
    Ok(env.new_string(vp_string).unwrap().into_inner())
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
    let vp_string = crate::did_auth(&holder, &linked_data_proof_options_json, &key_json)?;
    Ok(env.new_string(vp_string).unwrap().into_inner())
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
    let result_json = crate::verify_presentation(&vp_json, &linked_data_proof_options_json)?;
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
    let result_string = crate::resolve_did(&did, &input_metadata_json)?;
    Ok(env.new_string(result_string).unwrap().into_inner())
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
    let result_string = crate::dereference_did_url(&did_url, &input_metadata_json)?;
    Ok(env.new_string(result_string).unwrap().into_inner())
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
