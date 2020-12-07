use neon::prelude::*;

use ssi::jwk::JWK;
use ssi::vc::Credential as VerifiableCredential;
use ssi::vc::LinkedDataProofOptions;
use ssi::vc::Presentation as VerifiablePresentation;

use neon_serde::errors::Error as NeonSerdeError;
use ssi::error::Error as SsiError;

pub struct Error(pub String);

impl From<SsiError> for self::Error {
    fn from(err: SsiError) -> Error {
        self::Error(err.into())
    }
}

impl From<NeonSerdeError> for self::Error {
    fn from(err: NeonSerdeError) -> self::Error {
        self::Error(err.to_string())
    }
}

macro_rules! throws {
    ($cx:ident, $f:expr) => {
        match $f {
            Ok(v) => Ok(v),
            Err(e) => {
                let err: Error = e.into();
                $cx.throw_error(err.0)
            }
        }
    };
}

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
    let jwk = cx.argument::<JsValue>(0)?;
    let key: JWK = throws!(cx, neon_serde::from_value(&mut cx, jwk))?;

    let did = throws!(cx, key.to_did())?;
    Ok(cx.string(did))
}

pub fn key_to_verification_method(mut cx: FunctionContext) -> JsResult<JsString> {
    let jwk = cx.argument::<JsValue>(0)?;
    let key: JWK = throws!(cx, neon_serde::from_value(&mut cx, jwk))?;

    let verification_method = throws!(cx, key.to_verification_method())?;
    Ok(cx.string(verification_method))
}

fn issue_credential(mut cx: FunctionContext) -> JsResult<JsValue> {
    let credential = cx.argument::<JsValue>(0)?;
    let mut credential: VerifiableCredential =
        throws!(cx, neon_serde::from_value(&mut cx, credential))?;
    throws!(cx, credential.validate_unsigned())?;

    let linked_data_proof_options = cx.argument::<JsValue>(1)?;
    let options: LinkedDataProofOptions = throws!(
        cx,
        neon_serde::from_value(&mut cx, linked_data_proof_options)
    )?;

    let key = cx.argument::<JsValue>(2)?;
    let key: JWK = throws!(cx, neon_serde::from_value(&mut cx, key))?;

    let proof = throws!(cx, credential.generate_proof(&key, &options))?;
    credential.add_proof(proof);

    let vc = throws!(cx, neon_serde::to_value(&mut cx, &credential))?;
    Ok(vc)
}

fn verify_credential(mut cx: FunctionContext) -> JsResult<JsValue> {
    let vc = cx.argument::<JsValue>(0)?;
    let vc: VerifiableCredential = throws!(cx, neon_serde::from_value(&mut cx, vc))?;
    throws!(cx, vc.validate_unsigned())?;

    let ldpo = cx.argument::<JsValue>(1)?;
    let options: LinkedDataProofOptions = throws!(cx, neon_serde::from_value(&mut cx, ldpo))?;

    let result = vc.verify(Some(options));
    let result = throws!(cx, neon_serde::to_value(&mut cx, &result))?;
    Ok(result)
}

fn issue_presentation(mut cx: FunctionContext) -> JsResult<JsValue> {
    let presentation = cx.argument::<JsValue>(0)?;
    let mut presentation: VerifiablePresentation =
        throws!(cx, neon_serde::from_value(&mut cx, presentation))?;
    throws!(cx, presentation.validate_unsigned())?;

    let ldpo = cx.argument::<JsValue>(1)?;
    let options: LinkedDataProofOptions = throws!(cx, neon_serde::from_value(&mut cx, ldpo))?;

    let key = cx.argument::<JsValue>(2)?;
    let key: JWK = throws!(cx, neon_serde::from_value(&mut cx, key))?;

    let proof = throws!(cx, presentation.generate_proof(&key, &options))?;
    presentation.add_proof(proof);

    let vp = throws!(cx, neon_serde::to_value(&mut cx, &presentation))?;
    Ok(vp)
}

fn verify_presentation(mut cx: FunctionContext) -> JsResult<JsValue> {
    let vp = cx.argument::<JsValue>(0)?;
    let vp: VerifiablePresentation = throws!(cx, neon_serde::from_value(&mut cx, vp))?;
    throws!(cx, vp.validate_unsigned())?;

    let ldpo = cx.argument::<JsValue>(1)?;
    let options: LinkedDataProofOptions = throws!(cx, neon_serde::from_value(&mut cx, ldpo))?;

    let result = vp.verify(Some(options));
    let result = throws!(cx, neon_serde::to_value(&mut cx, &result))?;
    Ok(result)
}

register_module!(mut m, {
    m.export_function("getVersion", get_version)?;

    m.export_function("generateEd25519Key", generate_ed25519_key)?;
    m.export_function("keyToDID", key_to_did)?;
    m.export_function("keyToVerificationMethod", key_to_verification_method)?;

    m.export_function("issueCredential", issue_credential)?;
    m.export_function("verifyCredential", verify_credential)?;

    m.export_function("issuePresentation", issue_presentation)?;
    m.export_function("verifyPresentation", verify_presentation)?;

    Ok(())
});
