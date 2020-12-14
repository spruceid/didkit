use neon::prelude::*;

use ssi::jwk::JWK;
use ssi::vc::Credential as VerifiableCredential;
use ssi::vc::LinkedDataProofOptions;
use ssi::vc::Presentation as VerifiablePresentation;

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
    let key: JWK = arg!(cx, 0, JWK);
    let did = throws!(cx, key.to_did())?;
    Ok(cx.string(did))
}

pub fn key_to_verification_method(mut cx: FunctionContext) -> JsResult<JsString> {
    let key: JWK = arg!(cx, 0, JWK);
    let verification_method = throws!(cx, key.to_verification_method())?;
    Ok(cx.string(verification_method))
}

pub fn issue_credential(mut cx: FunctionContext) -> JsResult<JsValue> {
    let mut credential = arg!(cx, 0, VerifiableCredential);
    let options = arg!(cx, 1, LinkedDataProofOptions);
    let key = arg!(cx, 2, JWK);

    throws!(cx, credential.validate_unsigned())?;

    let proof = throws!(cx, credential.generate_proof(&key, &options))?;
    credential.add_proof(proof);

    let vc = throws!(cx, neon_serde::to_value(&mut cx, &credential))?;
    Ok(vc)
}

pub fn verify_credential(mut cx: FunctionContext) -> JsResult<JsValue> {
    let vc = arg!(cx, 0, VerifiableCredential);
    let options = arg!(cx, 1, LinkedDataProofOptions);

    throws!(cx, vc.validate_unsigned())?;

    let result = vc.verify(Some(options));
    let result = throws!(cx, neon_serde::to_value(&mut cx, &result))?;
    Ok(result)
}

pub fn issue_presentation(mut cx: FunctionContext) -> JsResult<JsValue> {
    let mut presentation = arg!(cx, 0, VerifiablePresentation);
    let options = arg!(cx, 1, LinkedDataProofOptions);
    let key = arg!(cx, 2, JWK);

    throws!(cx, presentation.validate_unsigned())?;

    let proof = throws!(cx, presentation.generate_proof(&key, &options))?;
    presentation.add_proof(proof);

    let vp = throws!(cx, neon_serde::to_value(&mut cx, &presentation))?;
    Ok(vp)
}

pub fn verify_presentation(mut cx: FunctionContext) -> JsResult<JsValue> {
    let vp = arg!(cx, 0, VerifiablePresentation);
    let options = arg!(cx, 1, LinkedDataProofOptions);

    throws!(cx, vp.validate_unsigned())?;

    let result = vp.verify(Some(options));
    let result = throws!(cx, neon_serde::to_value(&mut cx, &result))?;
    Ok(result)
}
