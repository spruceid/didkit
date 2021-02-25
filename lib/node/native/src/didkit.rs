use neon::prelude::*;

use didkit::error::Error as DIDKitError;
#[cfg(doc)]
use didkit::error::{didkit_error_code, didkit_error_message};
use didkit::get_verification_method;
use didkit::runtime;
use didkit::LinkedDataProofOptions;
use didkit::Source;
use didkit::VerifiableCredential;
use didkit::VerifiablePresentation;
use didkit::DID_METHODS;
use didkit::JWK;

use crate::error::Error;
use crate::{arg, throws};

pub static VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_version(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string(VERSION))
}

pub fn generate_ed25519_key(mut cx: FunctionContext) -> JsResult<JsValue> {
    let jwk = throws!(cx, JWK::generate_ed25519())?;
    let jwk_js = throws!(cx, neon_serde::to_value(&mut cx, &jwk))?;
    Ok(jwk_js)
}

pub fn key_to_did(mut cx: FunctionContext) -> JsResult<JsString> {
    let did_method: String = arg!(cx, 0, String);
    let key: JWK = arg!(cx, 1, JWK);

    let did_method = throws!(
        cx,
        DID_METHODS.get(&did_method).ok_or(DIDKitError::UnknownDIDMethod)
    )?;
    let did = throws!(
        cx,
        did_method
            .generate(&Source::Key(&key))
            .ok_or(DIDKitError::UnableToGenerateDID)
    )?;
    Ok(cx.string(did))
}

pub fn key_to_verification_method(mut cx: FunctionContext) -> JsResult<JsString> {
    let did_method: String = arg!(cx, 0, String);
    let key: JWK = arg!(cx, 1, JWK);

    let did_method = throws!(
        cx,
        DID_METHODS.get(&did_method).ok_or(DIDKitError::UnknownDIDMethod)
    )?;
    let did = throws!(
        cx,
        did_method
            .generate(&Source::Key(&key))
            .ok_or(DIDKitError::UnableToGenerateDID)
    )?;
    let did_resolver = did_method.to_resolver();
    let rt = throws!(cx, runtime::get())?;
    let vm = throws!(
        cx,
        rt.block_on(get_verification_method(&did, did_resolver))
            .ok_or(DIDKitError::UnableToGetVerificationMethod)
    )?;
    Ok(cx.string(vm))
}

pub fn issue_credential(mut cx: FunctionContext) -> JsResult<JsValue> {
    let mut credential = arg!(cx, 0, VerifiableCredential);
    let options = arg!(cx, 1, LinkedDataProofOptions);
    let key = arg!(cx, 2, JWK);

    let rt = throws!(cx, runtime::get())?;
    let proof = throws!(cx, rt.block_on(credential.generate_proof(&key, &options)))?;
    credential.add_proof(proof);

    let vc = throws!(cx, neon_serde::to_value(&mut cx, &credential))?;
    Ok(vc)
}

pub fn verify_credential(mut cx: FunctionContext) -> JsResult<JsValue> {
    let vc = arg!(cx, 0, VerifiableCredential);
    let options = arg!(cx, 1, LinkedDataProofOptions);

    let rt = throws!(cx, runtime::get())?;
    let result = rt.block_on(vc.verify(Some(options), DID_METHODS.to_resolver()));
    let result = throws!(cx, neon_serde::to_value(&mut cx, &result))?;
    Ok(result)
}

pub fn issue_presentation(mut cx: FunctionContext) -> JsResult<JsValue> {
    let mut presentation = arg!(cx, 0, VerifiablePresentation);
    let options = arg!(cx, 1, LinkedDataProofOptions);
    let key = arg!(cx, 2, JWK);

    let rt = throws!(cx, runtime::get())?;
    let proof = throws!(cx, rt.block_on(presentation.generate_proof(&key, &options)))?;
    presentation.add_proof(proof);

    let vp = throws!(cx, neon_serde::to_value(&mut cx, &presentation))?;
    Ok(vp)
}

pub fn did_auth(mut cx: FunctionContext) -> JsResult<JsValue> {
    let holder = arg!(cx, 0, String);
    let options = arg!(cx, 1, LinkedDataProofOptions);
    let key = arg!(cx, 2, JWK);

    let mut presentation = VerifiablePresentation::default();
    presentation.holder = Some(ssi::vc::URI::String(holder));

    let rt = throws!(cx, runtime::get())?;
    let proof = throws!(cx, rt.block_on(presentation.generate_proof(&key, &options)))?;
    presentation.add_proof(proof);

    let vp = throws!(cx, neon_serde::to_value(&mut cx, &presentation))?;
    Ok(vp)
}

pub fn verify_presentation(mut cx: FunctionContext) -> JsResult<JsValue> {
    let vp = arg!(cx, 0, VerifiablePresentation);
    let options = arg!(cx, 1, LinkedDataProofOptions);

    let rt = throws!(cx, runtime::get())?;
    let result = rt.block_on(vp.verify(Some(options), DID_METHODS.to_resolver()));
    let result = throws!(cx, neon_serde::to_value(&mut cx, &result))?;
    Ok(result)
}
