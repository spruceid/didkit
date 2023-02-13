use std::ptr;

use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

use crate::error::Error;
use crate::get_verification_method;
use crate::runtime;
use crate::ResolutionResult;
use crate::Source;
use crate::VerifiableCredential;
use crate::VerifiablePresentation;
use crate::DID_METHODS;
use crate::JWK;
use crate::{dereference, DereferencingInputMetadata, ResolutionInputMetadata};
use crate::{JWTOrLDPOptions, ProofFormat};

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

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_generateEd25519Key(env: &JNIEnv) -> Result<jstring, Error> {
    let jwk = JWK::generate_ed25519()?;
    let jwk_json = serde_json::to_string(&jwk)?;
    Ok(env.new_string(jwk_json).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_generateSecp256r1Key(env: &JNIEnv) -> Result<jstring, Error> {
    let jwk = JWK::generate_p256()?;
    let jwk_json = serde_json::to_string(&jwk)?;
    Ok(env.new_string(jwk_json).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_generateSecp256k1Key(env: &JNIEnv) -> Result<jstring, Error> {
    let jwk = JWK::generate_secp256k1()?;
    let jwk_json = serde_json::to_string(&jwk)?;
    Ok(env.new_string(jwk_json).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_generateSecp384r1Key(env: &JNIEnv) -> Result<jstring, Error> {
    let jwk = JWK::generate_p384()?;
    let jwk_json = serde_json::to_string(&jwk)?;
    Ok(env.new_string(jwk_json).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_keyToDID(
    env: &JNIEnv,
    method_pattern_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let method_pattern: String = env.get_string(method_pattern_jstring).unwrap().into();
    let key: JWK = serde_json::from_str(&key_json)?;
    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(&key, &method_pattern))
        .ok_or(Error::UnableToGenerateDID)?;
    Ok(env.new_string(did).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_keyToVerificationMethod(
    env: &JNIEnv,
    method_pattern_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let method_pattern: String = env.get_string(method_pattern_jstring).unwrap().into();
    let key: JWK = serde_json::from_str(&key_json)?;
    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(&key, &method_pattern))
        .ok_or(Error::UnableToGenerateDID)?;
    let did_resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let verification_method = rt
        .block_on(get_verification_method(&did, did_resolver))
        .ok_or(Error::UnableToGetVerificationMethod)?;
    Ok(env.new_string(verification_method).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_issueCredential(
    env: &JNIEnv,
    credential_jstring: JString,
    proof_options_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let credential_json: String = env.get_string(credential_jstring).unwrap().into();
    let proof_options_json: String = env.get_string(proof_options_jstring).unwrap().into();
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let mut credential = VerifiableCredential::from_json_unsigned(&credential_json)?;
    let key: JWK = serde_json::from_str(&key_json)?;
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options_json)?;
    let rt = runtime::get()?;
    let proof_format = options.proof_format.unwrap_or_default();
    let vc_string = match proof_format {
        ProofFormat::JWT => {
            rt.block_on(credential.generate_jwt(Some(&key), &options.ldp_options, resolver))?
        }
        ProofFormat::LDP => {
            let proof = rt.block_on(credential.generate_proof(
                &key,
                &options.ldp_options,
                resolver,
                &mut context_loader,
            ))?;
            credential.add_proof(proof);
            serde_json::to_string(&credential)?
        }
    };
    Ok(env.new_string(vc_string).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_verifyCredential(
    env: &JNIEnv,
    vc_jstring: JString,
    proof_options_jstring: JString,
) -> Result<jstring, Error> {
    let vc_string: String = env.get_string(vc_jstring).unwrap().into();
    let proof_options_json: String = env.get_string(proof_options_jstring).unwrap().into();
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options_json)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let rt = runtime::get()?;
    let result = match proof_format {
        ProofFormat::JWT => rt.block_on(VerifiableCredential::verify_jwt(
            &vc_string,
            Some(options.ldp_options),
            resolver,
            &mut context_loader,
        )),
        ProofFormat::LDP => {
            let vc = VerifiableCredential::from_json_unsigned(&vc_string)?;
            rt.block_on(vc.verify(Some(options.ldp_options), resolver, &mut context_loader))
        }
    };
    let result_json = serde_json::to_string(&result)?;
    Ok(env.new_string(result_json).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_issuePresentation(
    env: &JNIEnv,
    presentation_jstring: JString,
    proof_options_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let presentation_json: String = env.get_string(presentation_jstring).unwrap().into();
    let proof_options_json: String = env.get_string(proof_options_jstring).unwrap().into();
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let mut presentation = VerifiablePresentation::from_json_unsigned(&presentation_json)?;
    let key: JWK = serde_json::from_str(&key_json)?;
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options_json)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let rt = runtime::get()?;
    let vp_string = match proof_format {
        ProofFormat::JWT => {
            rt.block_on(presentation.generate_jwt(Some(&key), &options.ldp_options, resolver))?
        }
        ProofFormat::LDP => {
            let proof = rt.block_on(presentation.generate_proof(
                &key,
                &options.ldp_options,
                resolver,
                &mut context_loader,
            ))?;
            presentation.add_proof(proof);
            serde_json::to_string(&presentation)?
        }
    };
    Ok(env.new_string(vp_string).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_DIDAuth(
    env: &JNIEnv,
    holder_jstring: JString,
    proof_options_jstring: JString,
    key_jstring: JString,
) -> Result<jstring, Error> {
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let holder: String = env.get_string(holder_jstring).unwrap().into();
    let proof_options_json: String = env.get_string(proof_options_jstring).unwrap().into();
    let key_json: String = env.get_string(key_jstring).unwrap().into();
    let mut presentation = VerifiablePresentation {
        holder: Some(ssi::vc::URI::String(holder)),
        ..VerifiablePresentation::default()
    };
    let key: JWK = serde_json::from_str(&key_json)?;
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options_json)?;
    let proof_format = options.proof_format.unwrap_or_default();
    let rt = runtime::get()?;
    let vp_string = match proof_format {
        ProofFormat::JWT => {
            rt.block_on(presentation.generate_jwt(Some(&key), &options.ldp_options, resolver))?
        }
        ProofFormat::LDP => {
            let proof = rt.block_on(presentation.generate_proof(
                &key,
                &options.ldp_options,
                resolver,
                &mut context_loader,
            ))?;
            presentation.add_proof(proof);
            serde_json::to_string(&presentation)?
        }
    };
    Ok(env.new_string(vp_string).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_verifyPresentation(
    env: &JNIEnv,
    vp_jstring: JString,
    proof_options_jstring: JString,
) -> Result<jstring, Error> {
    let vp_string: String = env.get_string(vp_jstring).unwrap().into();
    let proof_options_json: String = env.get_string(proof_options_jstring).unwrap().into();
    let options: JWTOrLDPOptions = serde_json::from_str(&proof_options_json)?;
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let rt = runtime::get()?;
    let proof_format = options.proof_format.unwrap_or_default();
    let result = match proof_format {
        ProofFormat::JWT => rt.block_on(VerifiablePresentation::verify_jwt(
            &vp_string,
            Some(options.ldp_options),
            resolver,
            &mut context_loader,
        )),
        ProofFormat::LDP => {
            let vp = VerifiablePresentation::from_json_unsigned(&vp_string)?;
            rt.block_on(vp.verify(Some(options.ldp_options), resolver, &mut context_loader))
        }
    };
    let result_json = serde_json::to_string(&result)?;
    Ok(env.new_string(result_json).unwrap().into_inner())
}

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_resolveDID(
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

#[didkit_macros::java_export(wrap = "jstring_or_error")]
fn Java_com_spruceid_DIDKit_dereferenceDIDURL(
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
