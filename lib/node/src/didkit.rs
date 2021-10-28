use neon::prelude::*;

use didkit::error::Error as DIDKitError;
#[cfg(doc)]
use didkit::error::{didkit_error_code, didkit_error_message};
use didkit::get_verification_method;
use didkit::jwk_from_tezos_key as tz_to_jwk;
use didkit::runtime;
use didkit::ProofPreparation;
use didkit::Source;
use didkit::VerifiableCredential;
use didkit::VerifiablePresentation;
use didkit::DID_METHODS;
use didkit::JWK;
use didkit::URI;
use didkit::{Delegation, Invocation};
use didkit::{JWTOrLDPOptions, LinkedDataProofOptions, ProofFormat};
use didkit::{ResolutionInputMetadata, ResolutionResult};

use crate::error::Error;
use crate::{arg, throws};

type GenericInvocation = Invocation<serde_json::Value>;
type GenericDelegation = Delegation<serde_json::Value>;

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
    let method_pattern: String = arg!(cx, 0, String);
    let key: JWK = arg!(cx, 1, JWK);

    let did = throws!(
        cx,
        DID_METHODS
            .generate(&Source::KeyAndPattern(&key, &method_pattern))
            .ok_or(DIDKitError::UnableToGenerateDID)
    )?;
    Ok(cx.string(did))
}

pub fn key_to_verification_method(mut cx: FunctionContext) -> JsResult<JsString> {
    let method_pattern: String = arg!(cx, 0, String);
    let key: JWK = arg!(cx, 1, JWK);

    let did = throws!(
        cx,
        DID_METHODS
            .generate(&Source::KeyAndPattern(&key, &method_pattern))
            .ok_or(DIDKitError::UnableToGenerateDID)
    )?;
    let did_resolver = DID_METHODS.to_resolver();
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
    let options = arg!(cx, 1, JWTOrLDPOptions);
    let key = arg!(cx, 2, JWK);
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();

    let rt = throws!(cx, runtime::get())?;
    let vc = match proof_format {
        ProofFormat::JWT => {
            let jwt = throws!(
                cx,
                rt.block_on(credential.generate_jwt(Some(&key), &options.ldp_options, resolver))
            )?;
            cx.string(jwt).as_value(&mut cx)
        }
        ProofFormat::LDP => {
            let proof = throws!(
                cx,
                rt.block_on(credential.generate_proof(&key, &options.ldp_options, resolver))
            )?;
            credential.add_proof(proof);
            throws!(cx, neon_serde::to_value(&mut cx, &credential))?
        }
        _ => throws!(
            cx,
            Err(DIDKitError::UnknownProofFormat(proof_format.to_string()))
        )?,
    };
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
    let resolver = DID_METHODS.to_resolver();

    let rt = throws!(cx, runtime::get())?;
    let proof = throws!(
        cx,
        rt.block_on(presentation.generate_proof(&key, &options, resolver))
    )?;
    presentation.add_proof(proof);

    let vp = throws!(cx, neon_serde::to_value(&mut cx, &presentation))?;
    Ok(vp)
}

pub fn did_auth(mut cx: FunctionContext) -> JsResult<JsValue> {
    let holder = arg!(cx, 0, String);
    let options = arg!(cx, 1, LinkedDataProofOptions);
    let key = arg!(cx, 2, JWK);
    let resolver = DID_METHODS.to_resolver();

    let mut presentation = VerifiablePresentation::default();
    presentation.holder = Some(ssi::vc::URI::String(holder));

    let rt = throws!(cx, runtime::get())?;
    let proof = throws!(
        cx,
        rt.block_on(presentation.generate_proof(&key, &options, resolver))
    )?;
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

pub fn delegate_capability(mut cx: FunctionContext) -> JsResult<JsValue> {
    let del = arg!(cx, 0, GenericDelegation);
    let options = arg!(cx, 1, LinkedDataProofOptions);
    let parents = arg!(cx, 2, Vec<String>);
    let key = arg!(cx, 3, JWK);

    let rt = throws!(cx, runtime::get())?;
    let proof = throws!(
        cx,
        rt.block_on(del.generate_proof(
            &key,
            &options,
            DID_METHODS.to_resolver(),
            &parents.iter().map(|p| p.as_ref()).collect::<Vec<&str>>(),
        ))
    )?;
    let result = throws!(cx, neon_serde::to_value(&mut cx, &proof))?;
    Ok(result)
}

pub fn prepare_delegate_capability(mut cx: FunctionContext) -> JsResult<JsValue> {
    let del = arg!(cx, 0, GenericDelegation);
    let options = arg!(cx, 1, LinkedDataProofOptions);
    let parents = arg!(cx, 2, Vec<String>);
    let key = arg!(cx, 3, JWK);

    let rt = throws!(cx, runtime::get())?;
    let prep = throws!(
        cx,
        rt.block_on(del.prepare_proof(
            &key,
            &options,
            DID_METHODS.to_resolver(),
            &parents.iter().map(|p| p.as_ref()).collect::<Vec<&str>>(),
        ))
    )?;
    let result = throws!(cx, neon_serde::to_value(&mut cx, &prep))?;
    Ok(result)
}

pub fn complete_delegate_capability(mut cx: FunctionContext) -> JsResult<JsValue> {
    let del = arg!(cx, 0, GenericDelegation);
    let prep = arg!(cx, 1, ProofPreparation);
    let sig = arg!(cx, 2, String);

    let rt = throws!(cx, runtime::get())?;
    let proof = throws!(cx, rt.block_on(prep.complete(&sig)))?;
    let result = throws!(cx, neon_serde::to_value(&mut cx, &del.set_proof(proof)))?;
    Ok(result)
}

pub fn verify_delegation(mut cx: FunctionContext) -> JsResult<JsValue> {
    let del = arg!(cx, 0, GenericDelegation);
    let options = arg!(cx, 1, LinkedDataProofOptions);

    let rt = throws!(cx, runtime::get())?;
    let res = rt.block_on(del.verify(Some(options), DID_METHODS.to_resolver()));
    let result = throws!(cx, neon_serde::to_value(&mut cx, &res))?;
    Ok(result)
}

pub fn invoke_capability(mut cx: FunctionContext) -> JsResult<JsValue> {
    let inv = arg!(cx, 0, GenericInvocation);
    let target = arg!(cx, 1, URI);
    let options = arg!(cx, 2, LinkedDataProofOptions);
    let key = arg!(cx, 3, JWK);

    let rt = throws!(cx, runtime::get())?;
    let proof = throws!(
        cx,
        rt.block_on(inv.generate_proof(&key, &options, DID_METHODS.to_resolver(), &target))
    )?;
    let result = throws!(cx, neon_serde::to_value(&mut cx, &inv.set_proof(proof)))?;
    Ok(result)
}

pub fn prepare_invoke_capability(mut cx: FunctionContext) -> JsResult<JsValue> {
    let inv = arg!(cx, 0, GenericInvocation);
    let target = arg!(cx, 1, URI);
    let options = arg!(cx, 2, LinkedDataProofOptions);
    let key = arg!(cx, 3, JWK);

    let rt = throws!(cx, runtime::get())?;
    let prep = throws!(
        cx,
        rt.block_on(inv.prepare_proof(&key, &options, DID_METHODS.to_resolver(), &target))
    )?;
    let result = throws!(cx, neon_serde::to_value(&mut cx, &prep))?;
    Ok(result)
}

pub fn complete_invoke_capability(mut cx: FunctionContext) -> JsResult<JsValue> {
    let inv = arg!(cx, 0, GenericInvocation);
    let prep = arg!(cx, 1, ProofPreparation);
    let sig = arg!(cx, 2, String);

    let rt = throws!(cx, runtime::get())?;
    let res = throws!(cx, rt.block_on(prep.complete(&sig)))?;
    let result = throws!(cx, neon_serde::to_value(&mut cx, &inv.set_proof(res)))?;
    Ok(result)
}

pub fn verify_invocation(mut cx: FunctionContext) -> JsResult<JsValue> {
    let inv = arg!(cx, 0, GenericInvocation);
    let del = arg!(cx, 1, GenericDelegation);
    let options = arg!(cx, 2, LinkedDataProofOptions);

    let rt = throws!(cx, runtime::get())?;
    let res = rt.block_on(inv.verify(Some(options), DID_METHODS.to_resolver(), &del));
    let result = throws!(cx, neon_serde::to_value(&mut cx, &res))?;
    Ok(result)
}

pub fn verify_invocation_signature(mut cx: FunctionContext) -> JsResult<JsValue> {
    let inv = arg!(cx, 0, GenericInvocation);
    let options = arg!(cx, 1, LinkedDataProofOptions);

    let rt = throws!(cx, runtime::get())?;
    let res = rt.block_on(inv.verify_signature(Some(options), DID_METHODS.to_resolver()));
    let result = throws!(cx, neon_serde::to_value(&mut cx, &res))?;
    Ok(result)
}

pub fn jwk_from_tezos_key(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tzk = arg!(cx, 0, String);
    let jwk = throws!(cx, tz_to_jwk(&tzk))?;
    let result = throws!(cx, neon_serde::to_value(&mut cx, &jwk))?;
    Ok(result)
}

pub fn did_resolve(mut cx: FunctionContext) -> JsResult<JsValue> {
    let did = arg!(cx, 0, String);
    let input_metadata: ResolutionInputMetadata = arg!(cx, 1, ResolutionInputMetadata);
    let resolver = DID_METHODS.to_resolver();
    let rt = throws!(cx, runtime::get())?;
    let (res_meta, doc_opt, doc_meta_opt) = rt.block_on(resolver.resolve(&did, &input_metadata));
    let result = ResolutionResult {
        did_document: doc_opt,
        did_resolution_metadata: Some(res_meta),
        did_document_metadata: doc_meta_opt,
        ..Default::default()
    };
    let result = throws!(cx, neon_serde::to_value(&mut cx, &result))?;
    Ok(result)
}
