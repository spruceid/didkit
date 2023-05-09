use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::{c_char};
use std::ptr;

use serde::{Deserialize, Serialize};
use ssi::ldp::{ProofPreparation, ProofSuite, VerificationResult};
use ssi::vc::LinkedDataProofOptions;

use crate::error::Error;
#[cfg(doc)]
use crate::error::{didkit_error_code, didkit_error_message};
use crate::get_verification_method;
use crate::runtime;
use crate::Source;
use crate::VerifiableCredential;
use crate::VerifiablePresentation;
use crate::DID_METHODS;
use crate::JWK;
use crate::{dereference, DereferencingInputMetadata, ResolutionInputMetadata, ResolutionResult};
use crate::{JWTOrLDPOptions, ProofFormat};

/// The version of the DIDKit library, as a NULL-terminated string
pub static VERSION_C: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[no_mangle]
/// Get the version of the DIDKit library. Returns a static C string which should not be mutated or
/// freed.
pub extern "C" fn didkit_get_version() -> *const c_char {
    VERSION_C.as_ptr() as *const c_char
}

fn stash_err(error: Error) -> *const c_char {
    error.stash();
    ptr::null()
}

fn to_json_raw_ptr<T>(value: &T) -> Result<*const c_char, Error>
where
    T: ?Sized + Serialize
{
    serde_json::to_string(value).map_err(Error::from)
        .and_then(to_char_raw_ptr)
}


fn to_char_raw_ptr<T>(value: T) -> Result<*const c_char, Error>
where
    T: Into<Vec<u8>>
{
    CString::new(value).map_err(Error::from)
        .map(|s| s.into_raw() as *const c_char)
}

fn to_bas64_json_raw_ptr<T>(value: &T) -> Result<*const c_char, Error>
where
    T: ?Sized + Serialize
{
    serde_json::to_string(value).map_err(Error::from)
        .map(base64::encode)
        .and_then(to_char_raw_ptr)
}

fn string_from_raw_ptr(c_str: *const c_char) -> Result<String, Error> {
    unsafe{ CStr::from_ptr(c_str) }
        .to_str() //to_str() copies the bytes from c_str
        .map(String::from)
        .map_err(Error::from)
}

fn str_from_raw_ptr<'a>(c_str: *const c_char) -> Result<&'a str, Error> {
    unsafe{ CStr::from_ptr(c_str) }
        .to_str() //to_str() copies the bytes from c_str
        .map_err(Error::from)
}

fn string_or_default_from_raw_ptr(c_str: *const c_char, default: &str) -> Result<String, Error> {
    if c_str.is_null() {
        Ok(default.to_string())
    } else {
        string_from_raw_ptr(c_str)
    }
}

fn string_vec_from_string_array_raw_ptr(
    string_array_ptr: *const *const c_char,
    size: usize
) -> Result<Vec<String>, Error> {
    let mut string_vec: Vec<String> = Vec::with_capacity(size);
    for i in 0..size as isize {
        let cur_string_ptr = unsafe { string_array_ptr.offset(i) };
        let string = unsafe { string_from_raw_ptr(cur_string_ptr.read())? };
        string_vec.push(string);
    }
    Ok(string_vec)
}

fn from_json_raw_ptr<'a, T>(json_ptr: *const c_char) -> Result<T, Error>
where
    T:Deserialize<'a>
{
    str_from_raw_ptr(json_ptr)
        .and_then(|s| serde_json::from_str(s).map_err(Error::from))
}

/// We use VerifiablePresentation's json deserializer, instead of the generic serde one
fn presentation_from_raw_ptr(
    presentation_json_ptr: *const c_char
) -> Result<VerifiablePresentation, Error> {
    string_from_raw_ptr(presentation_json_ptr)
        .and_then(
            |s|
            VerifiablePresentation::from_json_unsigned(&s).map_err(Error::from)
        )
}

/// input_metadata has special default string handling, so we can't use the generic
/// from_json_raw_ptr
fn input_metadata_from_raw_ptr(
    input_metadata_json_ptr: *const c_char
) -> Result<ResolutionInputMetadata, Error> {
    string_or_default_from_raw_ptr(input_metadata_json_ptr, "{}")
        .and_then(|s| serde_json::from_str(&s).map_err(Error::from))
}

/// dereferencing_input_metadata has special default string handling, so we can't use the generic
/// from_json_raw_ptr
fn dereferencing_input_metadata_from_raw_ptr(
    input_metadata_json_ptr: *const c_char
) -> Result<DereferencingInputMetadata, Error> {
    string_or_default_from_raw_ptr(input_metadata_json_ptr, "{}")
        .and_then(|s| serde_json::from_str(&s).map_err(Error::from))
}


/// Calls a rust function with two arguments marshalled from C
///
/// # Arguments
/// * `arg_one_res` The result we will extract a value from for the first arg to rust_fun
/// * `arg_two_res` The result we will extract a value from for the second arg to rust_fun
/// * `rust_fun` is the rust function we wish to call
/// * `enc_fun` Translates the Ok value returned by rust_fun into something suitable for returning
///   to the c caller.  Typically this would be a newly allocated *const c_char
fn marshal_rust_from_c_2<T1, T2, RustFun, RustVal, EncFun, CVal>(
    arg_one_res: Result<T1, Error>,
    arg_two_res: Result<T2, Error>,
    rust_fun: RustFun,
    enc_fun: EncFun
) -> Result<CVal, Error>
where
    RustFun: Fn(T1, T2) -> Result<RustVal, Error>,
    EncFun: Fn(RustVal) -> Result<CVal, Error>
{
    let a1 = arg_one_res?;
    let a2 = arg_two_res?;
    let rust_val = rust_fun(a1, a2)?;
    enc_fun(rust_val)
}


/// Calls a rust function with two arguments marshalled from C
///
/// # Arguments
/// * `arg_one_res` The result we will extract a value from for the first arg to rust_fun
/// * `arg_two_res` The result we will extract a value from for the second arg to rust_fun
/// * `arg_three_res` The result we will extract a value from for the third arg to rust_fun
/// * `arg_four_res` The result we will extract a value from for the fourth arg to rust_fun
/// * `rust_fun` is the rust function we wish to call
/// * `enc_fun` Translates the Ok value returned by rust_fun into something suitable for returning
///   to the c caller.  Typically this would be a newly allocated *const c_char
fn marshal_rust_from_c_4<T1, T2, T3, T4, F, R>(
    arg_one_res: Result<T1, Error>,
    arg_two_res: Result<T2, Error>,
    arg_three_res: Result<T3, Error>,
    arg_four_res: Result<T4, Error>,
    rust_fun: RustFun,
    enc_fun: EncFun
) -> Result<CVal, Error>
where
    RustFun: Fn(T1, T2) -> Result<RustVal, Error>,
    EncFun: Fn(RustVal) -> Result<CVal, Error>
{
    let a1 = arg_one_res?;
    let a2 = arg_two_res?;
    let a3 = arg_three_res?;
    let a4 = arg_four_res?;
    let rust_val = rust_fun(a1, a2, a3, a4)?;
    enc_fun(rust_val)
}


/// Generate a new Ed25519 keypair in JWK format. On success, returns a pointer to a
/// newly-allocated string containing the JWK. The string must be freed with [`didkit_free_string`]. On
/// failure, returns `NULL`; the error message can be retrieved with [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_generate_ed25519_key() -> *const c_char {
    JWK::generate_ed25519().map_err(Error::from)
        .and_then(|jwk| to_json_raw_ptr(&jwk))
        .unwrap_or_else(stash_err)

}

/// Generate a new secp256r1 keypair in JWK format. On success, returns a pointer to a
/// newly-allocated string containing the JWK. The string must be freed with [`didkit_free_string`]. On
/// failure, returns `NULL`; the error message can be retrieved with [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_generate_secp256r1_key() -> *const c_char {
    JWK::generate_p256().map_err(Error::from)
        .and_then(|jwk| to_json_raw_ptr(&jwk))
        .unwrap_or_else(stash_err)
}

/// Generate a new secp256k1 keypair in JWK format. On success, returns a pointer to a
/// newly-allocated string containing the JWK. The string must be freed with [`didkit_free_string`]. On
/// failure, returns `NULL`; the error message can be retrieved with [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_generate_secp256k1_key() -> *const c_char {
    JWK::generate_secp256k1().map_err(Error::from)
        .and_then(|jwk| to_json_raw_ptr(&jwk))
        .unwrap_or_else(stash_err)
}

/// Generate a new secp384r1 keypair in JWK format. On success, returns a pointer to a
/// newly-allocated string containing the JWK. The string must be freed with [`didkit_free_string`]. On
/// failure, returns `NULL`; the error message can be retrieved with [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_generate_secp384r1_key() -> *const c_char {
    JWK::generate_p384().map_err(Error::from)
        .and_then(|jwk| to_json_raw_ptr(&jwk))
        .unwrap_or_else(stash_err)
}

/// Convert a key in JWK format to a did:key DID. Input should be a JWK containing public key
/// parameters. Private key parameters in the JWK are ignored. On success, returns a
/// newly-allocated C string containing a DID corresponding to the JWK. The returned string must be
/// freed
/// with [`didkit_free_string`].  On failure, returns `NULL`; the error message can be retrieved
/// with [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_key_to_did(
    method_pattern_ptr: *const c_char,
    key_json_ptr: *const c_char,
) -> *const c_char {
    marshal_rust_from_c_2(
        string_from_raw_ptr(method_pattern_ptr),
        from_json_raw_ptr::<JWK>(key_json_ptr),
        key_to_did,
        to_char_raw_ptr
    ).unwrap_or_else(stash_err)
}

fn key_to_did(method_pattern: String, jwk: JWK) -> Result<String, Error> {
    DID_METHODS
        .generate(&Source::KeyAndPattern(&jwk, &method_pattern))
        .ok_or(Error::UnableToGenerateDID)
}

/// Convert a key to a `did:key` DID URI for use in the `verificationMethod` property of a linked
/// data proof. Input should be a C string containing the key as a JWK. The JWK should contain
/// public key material; private key parameters are ignored. On success, this function returns a
/// newly-allocated C string containing the `verificationMethod` URI. On failure, `NULL` is
/// returned; the error message can be retrieved using [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_key_to_verification_method(
    method_pattern_ptr: *const c_char,
    key_json_ptr: *const c_char,
) -> *const c_char {
    string_from_raw_ptr(method_pattern_ptr)
        .and_then(
            |method_pattern|
            from_json_raw_ptr::<JWK>(key_json_ptr)
                .map(|jwk| (method_pattern, jwk))
        )
        .and_then(|(method_pattern, jwk)| key_to_verification_method(&method_pattern, jwk))
        .and_then(to_char_raw_ptr)
        .unwrap_or_else(stash_err)
}

fn key_to_verification_method(
    method_pattern: &str,
    jwk: JWK
) -> Result<String, Error> {
    let did_method = DID_METHODS
        .get(method_pattern)
        .ok_or(Error::UnknownDIDMethod)?;
    let did = did_method
        .generate(&Source::Key(&jwk))
        .ok_or(Error::UnableToGenerateDID)?;
    let did_resolver = did_method.to_resolver();
    let rt = runtime::get()?;
    rt.block_on(get_verification_method(&did, did_resolver))
        .ok_or(Error::UnableToGetVerificationMethod)
}


/// Issue a Verifiable Credential. Input parameters are JSON C strings for the unsigned credential
/// to be issued, the linked data proof options, and the JWK for signing.  On success, the
/// newly-issued verifiable credential is returned as a newly-allocated C string.  The returned
/// string should be freed using [`didkit_free_string`]. On failure, `NULL` is returned, and the
/// error message can be retrieved using [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_vc_issue_credential(
    credential_json_ptr: *const c_char,
    proof_options_json_ptr: *const c_char,
    key_json_ptr: *const c_char,
    context_loader_ptr: *const c_char,
) -> *const c_char {
    marshal_rust_from_c_4(
        from_json_raw_ptr::<VerifiableCredential>(credential_json_ptr),
        from_json_raw_ptr::<JWTOrLDPOptions>(proof_options_json_ptr),
        from_json_raw_ptr::<JWK>(key_json_ptr),
        load_context(context_loader_ptr),
        vc_issue_credential,
        to_char_raw_ptr
    ).unwrap_or_else(stash_err)
}



fn vc_issue_credential(
    credential: VerifiableCredential,
    proof_options: JWTOrLDPOptions,
    jwk: JWK,
    context_loader: ssi::jsonld::ContextLoader
) -> Result<String, Error> {
    let resolver = DID_METHODS.to_resolver();
    let proof_format = proof_options.proof_format.unwrap_or_default();
    let rt = runtime::get()?;
    match proof_format {
        ProofFormat::JWT => {
            rt
                .block_on(credential.generate_jwt(Some(&jwk), &proof_options.ldp_options, resolver))
                .map_err(Error::from)
        }
        ProofFormat::LDP => {
            let mut ctx = context_loader;
            let proof = rt.block_on(credential.generate_proof(
                &jwk,
                &proof_options.ldp_options,
                resolver,
                &mut ctx,
            ))?;
            let mut cred_with_proof = credential;
            cred_with_proof.add_proof(proof);
            serde_json::to_string(&cred_with_proof).map_err(Error::from)
        }
    }
}


/// Verify a Verifiable Credential. Arguments are a C string containing the Verifiable Credential to
/// verify, and a C string containing a JSON object for the linked data proof options for
/// verification. The return value is a newly-allocated C string containing a JSON object for the
/// verification result, or `NULL` in case of certain errors. On successful verification, the
/// verification result JSON object contains a "errors" property whose value is an empty array. If
/// verification fails, either `NULL` is returned and the error can be retrieved using
/// [`didkit_error_message`], or a verification result JSON object is returned with an "errors"
/// array containing information about the verification error(s) encountered. A string returned from
/// this function should be freed using [`didkit_free_string`].
#[no_mangle]
pub extern "C" fn didkit_vc_verify_credential(
    vc_str_ptr: *const c_char,
    proof_options_json_ptr: *const c_char,
    context_loader_ptr: *const c_char,
) -> *const c_char {
    string_from_raw_ptr(vc_str_ptr)
        .and_then(
            |vc_str|
            from_json_raw_ptr::<JWTOrLDPOptions>(proof_options_json_ptr)
                .map(|proof_options| (vc_str, proof_options))
        )
        .and_then(
            |(vc_str, proof_options)|
            load_context(context_loader_ptr)
                .map(|context| (vc_str, proof_options, context))
        )
        .and_then(
            |(vc_str, proof_options, context)|
            vc_verify_credential(&vc_str, proof_options, context)
        )
        .and_then(|verification_result| to_json_raw_ptr(&verification_result))
        .unwrap_or_else(stash_err)
}

fn vc_verify_credential(
    vc_str: &str,
    proof_options: JWTOrLDPOptions,
    context_loader: ssi::jsonld::ContextLoader
) -> Result<VerificationResult, Error> {
    let proof_format = proof_options.proof_format.unwrap_or_default();
    let rt = runtime::get()?;
    let resolver = DID_METHODS.to_resolver();
    let mut ctx = context_loader;
    let vr = match proof_format {
        ProofFormat::JWT => rt.block_on(VerifiableCredential::verify_jwt(
            vc_str,
            Some(proof_options.ldp_options),
            resolver,
            &mut ctx,
        )),
        ProofFormat::LDP => {
            let vc = VerifiableCredential::from_json_unsigned(vc_str)?;
            rt.block_on(vc.verify(Some(proof_options.ldp_options), resolver, &mut ctx))
        }
    };
    Ok(vr)
}


/// Issue a Verifiable Presentation. Input parameters are JSON C strings for the unsigned
/// presentation to be issued, the linked data proof options, and the JWK for signing. On success,
/// the newly-issued verifiable presentation is returned as a newly-allocated C string. The returned
/// string should be freed using [`didkit_free_string`]. On failure, `NULL` is returned, and the
/// error message can be retrieved using [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_vc_issue_presentation(
    presentation_json_ptr: *const c_char,
    proof_options_json_ptr: *const c_char,
    key_json_ptr: *const c_char,
    context_loader_ptr: *const c_char,
) -> *const c_char {
    presentation_from_raw_ptr(presentation_json_ptr)
        .and_then(
            |presentation|
            from_json_raw_ptr::<JWTOrLDPOptions>(proof_options_json_ptr)
                .map(|proof_options| (presentation, proof_options))
        )
        .and_then(
            |(presentation, proof_options)|
            from_json_raw_ptr::<JWK>(key_json_ptr).map(|jwk| (presentation, proof_options, jwk))
        )
        .and_then(
            |(presentation, proof_options, jwk)|
            load_context(context_loader_ptr)
                .map(|context_loader| (presentation, proof_options, jwk, context_loader))
        )
        .and_then(
            |(presentation, proof_options, jwk, context_loader)|
            vc_issue_presentation(presentation, proof_options, jwk, context_loader)
        )
        .and_then(to_char_raw_ptr)
        .unwrap_or_else(stash_err)
}

fn vc_issue_presentation(
    presentation: VerifiablePresentation,
    proof_options: JWTOrLDPOptions,
    jwk: JWK,
    context_loader: ssi::jsonld::ContextLoader
) -> Result<String, Error> {
    let resolver = DID_METHODS.to_resolver();
    let proof_format = proof_options.proof_format.unwrap_or_default();
    let rt = runtime::get()?;
    match proof_format {
        ProofFormat::JWT => {
            rt.block_on(
                presentation.generate_jwt(Some(&jwk), &proof_options.ldp_options, resolver)
            ).map_err(Error::from)
        }
        ProofFormat::LDP => {
            let mut ctx = context_loader;
            let proof = rt.block_on(presentation.generate_proof(
                &jwk,
                &proof_options.ldp_options,
                resolver,
                &mut ctx
            ))?;
            let mut presentation_with_proof = presentation;
            presentation_with_proof.add_proof(proof);
            serde_json::to_string(&presentation_with_proof).map_err(Error::from)
        }
    }
}



/// Verify a Verifiable Presentation. Arguments are a C string containing the Verifiable
/// Presentation to verify, and a C string containing a JSON object for the linked data proof
/// options for verification. The return value is a newly-allocated C string containing a JSON
/// object for the verification result, or `NULL` in case of certain errors. On successful
/// verification, the verification result JSON object contains a "errors" property whose value is an
/// empty array. If verification fails, either `NULL` is returned and the error can be retrieved
/// using [`didkit_error_message`], or a verification result JSON object is returned with an
/// "errors" array containing information about the verification error(s) encountered. A string
/// returned from this function should be freed using [`didkit_free_string`].
#[no_mangle]
pub extern "C" fn didkit_vc_verify_presentation(
    vp_str_ptr: *const c_char,
    proof_options_json_ptr: *const c_char,
    context_loader_ptr: *const c_char,
) -> *const c_char {
    string_from_raw_ptr(vp_str_ptr)
        .and_then(
            |vp_str|
            from_json_raw_ptr::<JWTOrLDPOptions>(proof_options_json_ptr)
                .map(|proof_options| (vp_str, proof_options))
        )
        .and_then(
            |(vp_str, proof_options)|
            load_context(context_loader_ptr)
                .map(|context_loader| (vp_str, proof_options, context_loader))
        )
        .and_then(
            |(vp_str, proof_options, context_loader)|
            vc_verify_presentation(&vp_str, proof_options, context_loader)
        )
        .and_then(|vr| to_json_raw_ptr(&vr))
        .unwrap_or_else(stash_err)
}


fn vc_verify_presentation(
    vp_str: &str,
    proof_options: JWTOrLDPOptions,
    context_loader: ssi::jsonld::ContextLoader
) -> Result<VerificationResult, Error> {
    let proof_format = proof_options.proof_format.unwrap_or_default();
    let rt = runtime::get()?;
    let resolver = DID_METHODS.to_resolver();
    let mut ctx = context_loader;
    let vr = match proof_format {
        ProofFormat::JWT => rt.block_on(VerifiablePresentation::verify_jwt(
            vp_str,
            Some(proof_options.ldp_options),
            resolver,
            &mut ctx,
        )),
        ProofFormat::LDP => {
            let vp = VerifiablePresentation::from_json_unsigned(vp_str)?;
            rt.block_on(vp.verify(
                Some(proof_options.ldp_options),
                DID_METHODS.to_resolver(),
                &mut ctx,
            ))
        }
    };
    Ok(vr)
}

/// Issue a Verifiable Presentation for
/// [DIDAuth](https://w3c-ccg.github.io/vp-request-spec/#did-authentication-request). Input
/// parameters are the holder URI as a C string, and JSON C strings for the linked data proof
/// options and the JWK for signing. On success, a newly-issued verifiable presentation is returned
/// as a newly-allocated C string. The returned string should be freed using
/// [`didkit_free_string`]. On failure, `NULL` is returned, and the error message can be retrieved
/// using [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_did_auth(
    holder_ptr: *const c_char,
    proof_options_json_ptr: *const c_char,
    key_json_ptr: *const c_char,
    context_loader_ptr: *const c_char,
) -> *const c_char {
    string_from_raw_ptr(holder_ptr)
        .and_then(
            |holder|
            from_json_raw_ptr::<JWTOrLDPOptions>(proof_options_json_ptr)
                .map(|proof_options| (holder, proof_options))
        )
        .and_then(
            |(holder, proof_options)|
            from_json_raw_ptr::<JWK>(key_json_ptr)
                .map(|jwk| (holder, proof_options, jwk))
        )
        .and_then(
            |(holder, proof_options, jwk)|
            load_context(context_loader_ptr)
                .map(|context_loader| (holder, proof_options, jwk, context_loader))
        )
        .and_then(
            |(holder, proof_options, jwk, context_loader)|
            did_auth(holder, proof_options, jwk, context_loader)
        )
        .and_then(to_char_raw_ptr)
        .unwrap_or_else(stash_err)
}


fn did_auth(
    holder: String,
    proof_options: JWTOrLDPOptions,
    jwk: JWK,
    context_loader: ssi::jsonld::ContextLoader
) -> Result<String, Error> {
    let resolver = DID_METHODS.to_resolver();
    let mut presentation = VerifiablePresentation {
        holder: Some(ssi::vc::URI::String(holder)),
        ..VerifiablePresentation::default()
    };

    let proof_format = proof_options.proof_format.unwrap_or_default();
    let rt = runtime::get()?;
    match proof_format {
        ProofFormat::JWT => {
            rt.block_on(
                presentation.generate_jwt(Some(&jwk), &proof_options.ldp_options, resolver)
            ).map_err(Error::from)
        }
        ProofFormat::LDP => {
            let mut ctx = context_loader;
            let proof = rt.block_on(presentation.generate_proof(
                &jwk,
                &proof_options.ldp_options,
                resolver,
                &mut ctx
            ))?;
            presentation.add_proof(proof);
            serde_json::to_string(&presentation).map_err(Error::from)
        }
    }
}

/// Resolve a DID to a DID Document. Arguments are a C string containing the DID to resolve, and a
/// C string containing a JSON object for resolution input metadata. The return value on success is
/// a newly-allocated C string containing either the resolved DID document or a DID resolution
/// result JSON object. On error, `NULL` is returned, and the error can be retrieved using
/// [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_resolve_did(
    did_ptr: *const c_char,
    input_metadata_json_ptr: *const c_char,
) -> *const c_char {
    string_from_raw_ptr(did_ptr)
        .and_then(
            |did|
            input_metadata_from_raw_ptr(input_metadata_json_ptr)
                .map(|input_metadata| (did, input_metadata))
        )
        .and_then(
            |(did, input_metadata)|
            resolve_did(&did, input_metadata)
        )
        .and_then(|res_result| to_json_raw_ptr(&res_result))
        .unwrap_or_else(stash_err)
}


fn resolve_did(
    did: &str,
    input_metadata: ResolutionInputMetadata
) -> Result<ResolutionResult, Error> {
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let (res_meta, doc_opt, doc_meta_opt) = rt.block_on(resolver.resolve(did, &input_metadata));
    let res_result = ResolutionResult {
        did_document: doc_opt,
        did_resolution_metadata: Some(res_meta),
        did_document_metadata: doc_meta_opt,
        ..Default::default()
    };
    Ok(res_result)
}


/// Resolve a DID to a DID Document. Arguments are a C string containing the DID URL to dereference,
/// and a C string containing a JSON object for dereferencing input metadata. The return value on
/// success is a newly-allocated C string containing either a resolved resource or a DID resolution
/// result JSON object. On error, `NULL` is returned, and the error can be retrieved using
/// [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_dereference_did_url(
    did_url_ptr: *const c_char,
    input_metadata_json_ptr: *const c_char,
) -> *const c_char {
    string_from_raw_ptr(did_url_ptr)
        .and_then(
            |did_url|
            dereferencing_input_metadata_from_raw_ptr(input_metadata_json_ptr)
                .map(|input_metadata| (did_url, input_metadata))
        )
        .and_then(
            |(did_url, input_metadata)|
            dereference_did_url(&did_url, input_metadata)
        )
        .and_then(to_char_raw_ptr)
        .unwrap_or_else(stash_err)
}


fn dereference_did_url(
    did_url: &str,
    input_metadata: DereferencingInputMetadata
) -> Result<String, Error> {
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let deref_result = rt.block_on(dereference(resolver, did_url, &input_metadata));
    use serde_json::json;
    let result = json!(deref_result);
    serde_json::to_string(&result).map_err(Error::from)
}


#[derive(Serialize, Deserialize)]
struct Context {
    url: String,
    json: String,
}

impl Context {
    fn into_pair(self) -> (String, String) {
        (self.url, self.json)
    }
}

#[no_mangle]
pub extern "C" fn didkit_create_context(
    url_ptr: *const c_char,
    json_ptr: *const c_char
) -> *const c_char {
    string_from_raw_ptr(url_ptr)
        .and_then(
            |url|
            string_from_raw_ptr(json_ptr).map(|json| (url, json))
        )
        .map(|(url, json)| Context{url, json})
        .and_then(|ctx| to_bas64_json_raw_ptr(&ctx))
        .unwrap_or_else(stash_err)
}


#[no_mangle]
pub extern "C" fn didkit_create_context_map(
    contexts_ptr: *const *const c_char,
    size: usize,
) -> *const c_char {
    string_vec_from_string_array_raw_ptr(contexts_ptr, size)
        .and_then(|ctx| to_bas64_json_raw_ptr(&ctx))
        .unwrap_or_else(stash_err)
}

fn load_context(context_loader_ptr: *const c_char) -> Result<ssi::jsonld::ContextLoader, Error> {
    if !context_loader_ptr.is_null() {
        let encoded = unsafe { CStr::from_ptr(context_loader_ptr) }.to_str()?;
        let json = base64::decode(encoded)?;
        let contexts: Vec<String> = serde_json::from_slice(&json)?;
        let map: HashMap<String, String> = contexts
            .into_iter()
            .map(base64::decode)
            .collect::<Result<Vec<Vec<u8>>, _>>()?
            .into_iter()
            .map(|e| serde_json::from_slice(e.as_slice()))
            .collect::<Result<Vec<Context>, _>>()?
            .into_iter()
            .map(Context::into_pair)
            .collect();
        Ok(ssi::jsonld::ContextLoader::default().with_context_map_from(map)?)
    } else {
        Ok(ssi::jsonld::ContextLoader::default())
    }
}



/// Prepares a credential for signing by an external service.
///
/// All parameters are pointers to json encoded strings.
///
/// The return is a json serialized proof preparation object which should be treated as
/// opaque by calling applications.   It is necessary in the call to complete the credential
/// issuance.
#[no_mangle]
pub extern "C" fn didkit_vc_prepare_issue_credential(
    credential_ptr: *const c_char,
    linked_data_proof_options_ptr: *const c_char,
    public_key_ptr: *const c_char,
    context_loader_ptr: *const c_char,
) -> *const c_char {
    from_json_raw_ptr::<VerifiableCredential>(credential_ptr)
        .and_then(
            |credential|
            from_json_raw_ptr::<LinkedDataProofOptions>(linked_data_proof_options_ptr)
                .map(|proof_options| (credential, proof_options))
        )
        .and_then(
            |(credential, proof_options)|
            from_json_raw_ptr::<JWK>(public_key_ptr).map(|jwk| (credential, proof_options, jwk))
        )
        .and_then(
            |(credential, proof_options, jwk)|
            load_context(context_loader_ptr).map(|ctx| (credential, proof_options, jwk, ctx))
        )
        .and_then(
            |(credential, proof_options, jwk, ctx)|
            vc_prepare_issue_credential(credential, proof_options, jwk, ctx)
        )
        .and_then(|preparation| to_json_raw_ptr(&preparation))
        .unwrap_or_else(stash_err)
}


/// Prepares a credential for signing by an external service.
fn vc_prepare_issue_credential(
    credential: VerifiableCredential,
    linked_data_proof_options: LinkedDataProofOptions,
    jwk: JWK,
    context_loader: ssi::jsonld::ContextLoader
) -> Result<ProofPreparation, Error> {
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let mut ctx = context_loader;
    rt.block_on(credential.prepare_proof(
        &jwk,
        &linked_data_proof_options,
        resolver,
        &mut ctx,
    )).map_err(Error::from)
}


/// Completes credential issuance after obtaining a signature from an external service.
///
/// credential_ptr should be the same as the credential_ptr used in
/// didkit_vc_prepare_issue_credential
///
/// preparation_ptr should be the return from didkit_vc_parepare_issue_credential
///
/// signature_ptr should be the signature returned from the external signing service.  It must be
/// of a form specified in the verification method of the credential.
#[no_mangle]
pub extern "C" fn didkit_vc_complete_issue_credential(
    credential_ptr: *const c_char,
    preparation_ptr: *const c_char,
    signature_ptr: *const c_char,
) -> *const c_char {
    from_json_raw_ptr::<VerifiableCredential>(credential_ptr)
        .and_then(
            |credential|
            from_json_raw_ptr::<ProofPreparation>(preparation_ptr)
                .map(|preparation| (credential, preparation))
        )
        .and_then(
            |(credential, preparation)|
            string_from_raw_ptr(signature_ptr).map(|signature| (credential, preparation, signature))
        )
        .and_then(
            |(credential, preparation, signature)|
            vc_complete_issue_credential(credential, preparation, signature)
        )
        .and_then(|credential| to_json_raw_ptr(&credential))
        .unwrap_or_else(stash_err)
}


fn vc_complete_issue_credential(
    credential: VerifiableCredential,
    preparation: ProofPreparation,
    signature: String
) -> Result<VerifiableCredential, Error> {
    let rt = runtime::get()?;
    let proof = rt.block_on(preparation.proof.type_.complete(&preparation, &signature))?;
    let mut credential_with_proof = credential;
    credential_with_proof.add_proof(proof);
    Ok(credential_with_proof)
}


#[no_mangle]
pub extern "C" fn didkit_vc_prepare_issue_presentation(
    presentation_ptr: *const c_char,
    linked_data_proof_options_ptr: *const c_char,
    public_key_ptr: *const c_char,
    context_loader_ptr: *const c_char,
) -> *const c_char {
    presentation_from_raw_ptr(presentation_ptr)
        .and_then(
            |presentation|
            from_json_raw_ptr::<LinkedDataProofOptions>(linked_data_proof_options_ptr)
                .map(|proof_options| (presentation, proof_options))
        )
        .and_then(
            |(presentation, proof_options)|
            from_json_raw_ptr::<JWK>(public_key_ptr).map(|jwk| (presentation, proof_options, jwk))
        )
        .and_then(
            |(presentation, proof_options, jwk)|
            load_context(context_loader_ptr).map(|ctx| (presentation, proof_options, jwk, ctx))
        )
        .and_then(
            |(presentation, proof_options, jwk, ctx)|
            vc_prepare_issue_presentation(presentation, proof_options, jwk, ctx)
        )
        .and_then(|preparation| to_json_raw_ptr(&preparation))
        .unwrap_or_else(stash_err  )
}



/// Prepares a presentation for signing by an external service.
///
/// All parameters are pointers to json encoded strings.
///
/// The return is a json serialized proof preparation object which should be treated as
/// opaque by calling applications.   It is necessary in the call to complete the presentation
/// issuance.
fn vc_prepare_issue_presentation(
    presentation: VerifiablePresentation,
    linked_data_proof_options: LinkedDataProofOptions,
    jwk: JWK,
    context_loader: ssi::jsonld::ContextLoader
) -> Result<ProofPreparation, Error> {
    let resolver = DID_METHODS.to_resolver();
    let rt = runtime::get()?;
    let mut ctx = context_loader;
    rt.block_on(presentation.prepare_proof(
        &jwk,
        &linked_data_proof_options,
        resolver,
        &mut ctx,
    )).map_err(Error::from)
}

/// Completes presentation issuance after obtaining a signature from an external service.
///
/// presentation_ptr should be the same as the presentation_ptr used in
/// didkit_vc_prepare_issue_presentation
///
/// preparation_ptr should be the return from didkit_vc_parepare_issue_presentation
///
/// signature_ptr should be the signature returned from the external signing service.  It must be
/// of a form specified in the verification method of the credential.
#[no_mangle]
pub extern "C" fn didkit_vc_complete_issue_presentation(
    presentation_ptr: *const c_char,
    preparation_ptr: *const c_char,
    signature_ptr: *const c_char,
) -> *const c_char {
    presentation_from_raw_ptr(presentation_ptr)
        .and_then(
            |presentation|
            from_json_raw_ptr::<ProofPreparation>(preparation_ptr)
                .map(|preparation| (presentation, preparation))
        )
        .and_then(
            |(presentation, preparation)|
            string_from_raw_ptr(signature_ptr)
                .map(|signature| (presentation, preparation, signature))
        )
        .and_then(
            |(presentation, preparation, signature)|
            vc_complete_issue_presentation(presentation, preparation, signature)
        )
        .and_then(|presentation| to_json_raw_ptr(&presentation))
        .unwrap_or_else(stash_err)
}

fn vc_complete_issue_presentation(
    presentation: VerifiablePresentation,
    preparation: ProofPreparation,
    signature: String
) -> Result<VerifiablePresentation, Error> {
    let rt = runtime::get()?;
    let proof = rt.block_on(preparation.proof.type_.complete(&preparation, &signature))?;
    let mut presentation_with_proof = presentation;
    presentation_with_proof.add_proof(proof);
    Ok(presentation_with_proof)
}


// TODO: didkit_delegate_capability
// TODO: didkit_prepare_delegate_capability
// TODO: didkit_complete_delegate_capability
// TODO: didkit_verify_delegation
// TODO: didkit_invoke_capability
// TODO: didkit_prepare_invoke_capability
// TODO: didkit_complete_invoke_capability
// TODO: didkit_verify_invocation_signature
// TODO: didkit_verify_invocation

#[no_mangle]
/// Free a C string that has been dynamically allocated by DIDKit. This should be used for strings
/// returned from most DIDKit C functions, per their respective documentation.
pub extern "C" fn didkit_free_string(string: *const c_char) {
    if string.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(string as *mut c_char));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_version() {
        let version = didkit_get_version();
        let version_cstr = unsafe { CStr::from_ptr(version) };
        let version_str = version_cstr.to_str().unwrap();
        assert!(version_str.len() > 0);
    }
}
