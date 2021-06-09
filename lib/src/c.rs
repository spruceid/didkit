use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use crate::error::Error;
#[cfg(doc)]
use crate::error::{didkit_error_code, didkit_error_message};

/// The version of the DIDKit library, as a NULL-terminated string
pub static VERSION_C: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[no_mangle]
/// Get the version of the DIDKit library. Returns a static C string which should not be mutated or
/// freed.
pub extern "C" fn didkit_get_version() -> *const c_char {
    VERSION_C.as_ptr() as *const c_char
}

fn ccchar_or_error(result: Result<*const c_char, Error>) -> *const c_char {
    // On success, pass through the string. On error, save the error for retrieval using
    // didkit_error_message, and return NULL.
    match result {
        Ok(ccchar) => ccchar,
        Err(error) => {
            error.stash();
            ptr::null()
        }
    }
}

// TODO: instead of having two of each function, make a procedural macro to wrap each function.  Or
// implement std::ops::Try (nightly).

// Generate Ed25519 key
fn generate_ed25519_key() -> Result<*const c_char, Error> {
    let jwk_string = crate::generate_ed25519_key()?;
    Ok(CString::new(jwk_string)?.into_raw())
}
/// Generate a new Ed25519 keypair in JWK format. On success, returns a pointer to a
/// newly-allocated string containing the JWK. The string must be freed with [`didkit_free_string`]. On
/// failure, returns `NULL`; the error message can be retrieved with [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_vc_generate_ed25519_key() -> *const c_char {
    ccchar_or_error(generate_ed25519_key())
}

// Convert JWK to did:key DID
fn key_to_did(
    method_pattern_ptr: *const c_char,
    key_json_ptr: *const c_char,
) -> Result<*const c_char, Error> {
    let method_pattern = unsafe { CStr::from_ptr(method_pattern_ptr) }.to_str()?;
    let key_json = unsafe { CStr::from_ptr(key_json_ptr) }.to_str()?;
    let did = crate::key_to_did(method_pattern, key_json)?;
    Ok(CString::new(did)?.into_raw())
}
#[no_mangle]
/// Convert a key in JWK format to a did:key DID. Input should be a JWK containing public key
/// parameters. Private key parameters in the JWK are ignored. On success, returns a
/// newly-allocated C string containing a DID corresponding to the JWK. The returned string must be
/// freed
/// with [`didkit_free_string`].  On failure, returns `NULL`; the error message can be retrieved
/// with [`didkit_error_message`].
pub extern "C" fn didkit_key_to_did(
    method_pattern: *const c_char,
    jwk: *const c_char,
) -> *const c_char {
    ccchar_or_error(key_to_did(method_pattern, jwk))
}

// Convert JWK to did:key DID URI for verificationMethod
fn key_to_verification_method(
    method_pattern_ptr: *const c_char,
    key_json_ptr: *const c_char,
) -> Result<*const c_char, Error> {
    let method_pattern = unsafe { CStr::from_ptr(method_pattern_ptr) }.to_str()?;
    let key_json = unsafe { CStr::from_ptr(key_json_ptr) }.to_str()?;
    let vm = crate::key_to_verification_method(method_pattern, key_json)?;
    Ok(CString::new(vm)?.into_raw())
}
/// Convert a key to a `did:key` DID URI for use in the `verificationMethod` property of a linked data
/// proof. Input should be a C string containing the key as a JWK. The JWK should contain public
/// key material; private key parameters are ignored. On success, this function returns a newly-allocated C string containing the `verificationMethod` URI. On failure, `NULL` is returned; the
/// error message can be retrieved using [`didkit_error_message`].
#[no_mangle]
pub extern "C" fn didkit_key_to_verification_method(
    method_pattern: *const c_char,
    jwk: *const c_char,
) -> *const c_char {
    ccchar_or_error(key_to_verification_method(method_pattern, jwk))
}

// Issue Credential
fn issue_credential(
    credential_json_ptr: *const c_char,
    linked_data_proof_options_json_ptr: *const c_char,
    key_json_ptr: *const c_char,
) -> Result<*const c_char, Error> {
    let credential_json = unsafe { CStr::from_ptr(credential_json_ptr) }.to_str()?;
    let linked_data_proof_options_json =
        unsafe { CStr::from_ptr(linked_data_proof_options_json_ptr) }.to_str()?;
    let key_json = unsafe { CStr::from_ptr(key_json_ptr) }.to_str()?;
    let vc_string =
        crate::issue_credential(credential_json, linked_data_proof_options_json, key_json)?;
    Ok(CString::new(vc_string)?.into_raw())
}
#[no_mangle]
/// Issue a Verifiable Credential. Input parameters are JSON C strings for the unsigned credential
/// to be issued, the linked data proof options, and the JWK for signing.  On success, the
/// newly-issued verifiable credential is returned as a newly-allocated C string.  The returned
/// string should be freed using [`didkit_free_string`]. On failure, `NULL` is returned, and the error
/// message can be retrieved using [`didkit_error_message`].
pub extern "C" fn didkit_vc_issue_credential(
    credential_json: *const c_char,
    linked_data_proof_options_json: *const c_char,
    key_json: *const c_char,
) -> *const c_char {
    ccchar_or_error(issue_credential(
        credential_json,
        linked_data_proof_options_json,
        key_json,
    ))
}

// Verify Credential
fn verify_credential(
    credential_json_ptr: *const c_char,
    linked_data_proof_options_json_ptr: *const c_char,
) -> Result<*const c_char, Error> {
    let credential_json = unsafe { CStr::from_ptr(credential_json_ptr) }.to_str()?;
    let linked_data_proof_options_json =
        unsafe { CStr::from_ptr(linked_data_proof_options_json_ptr) }.to_str()?;
    let result_json = crate::verify_credential(credential_json, linked_data_proof_options_json)?;
    Ok(CString::new(result_json)?.into_raw())
}
#[no_mangle]
/// Verify a Verifiable Credential. Arguments are a C string containing the Verifiable Credential
/// to verify, and a C string containing a JSON object for the linked data proof options for
/// verification. The return value is a newly-allocated C string containing a JSON object for the
/// verification result, or `NULL` in case of certain errors. On successful verification, the
/// verification result JSON object contains a "errors" property whose value is an empty array. If
/// verification fails, either `NULL` is returned and the error can be retrieved using
/// [`didkit_error_message`], or a verification result JSON object is returned with an "errors" array
/// containing information about the verification error(s) encountered. A string returned from this
/// function should be freed using [`didkit_free_string`].
pub extern "C" fn didkit_vc_verify_credential(
    credential_json: *const c_char,
    linked_data_proof_options_json: *const c_char,
) -> *const c_char {
    ccchar_or_error(verify_credential(
        credential_json,
        linked_data_proof_options_json,
    ))
}

// Issue Presentation
fn issue_presentation(
    presentation_json_ptr: *const c_char,
    linked_data_proof_options_json_ptr: *const c_char,
    key_json_ptr: *const c_char,
) -> Result<*const c_char, Error> {
    let presentation_json = unsafe { CStr::from_ptr(presentation_json_ptr) }.to_str()?;
    let linked_data_proof_options_json =
        unsafe { CStr::from_ptr(linked_data_proof_options_json_ptr) }.to_str()?;
    let key_json = unsafe { CStr::from_ptr(key_json_ptr) }.to_str()?;
    let vp_string =
        crate::issue_presentation(presentation_json, linked_data_proof_options_json, key_json)?;
    Ok(CString::new(vp_string)?.into_raw())
}
#[no_mangle]
/// Issue a Verifiable Presentation. Input parameters are JSON C strings for the unsigned
/// presentation to be issued, the linked data proof options, and the JWK for signing. On success,
/// the newly-issued verifiable presentation is returned as a newly-allocated C string. The
/// returned string should be freed using [`didkit_free_string`]. On failure, `NULL` is returned, and the
/// error message can be retrieved using [`didkit_error_message`].
pub extern "C" fn didkit_vc_issue_presentation(
    presentation_json: *const c_char,
    linked_data_proof_options_json: *const c_char,
    key_json: *const c_char,
) -> *const c_char {
    ccchar_or_error(issue_presentation(
        presentation_json,
        linked_data_proof_options_json,
        key_json,
    ))
}

// Issue Presentation (DIDAuth)
fn did_auth(
    holder_ptr: *const c_char,
    linked_data_proof_options_json_ptr: *const c_char,
    key_json_ptr: *const c_char,
) -> Result<*const c_char, Error> {
    let holder = unsafe { CStr::from_ptr(holder_ptr) }.to_str()?;
    let linked_data_proof_options_json =
        unsafe { CStr::from_ptr(linked_data_proof_options_json_ptr) }.to_str()?;
    let key_json = unsafe { CStr::from_ptr(key_json_ptr) }.to_str()?;
    let vp_string = crate::did_auth(holder, linked_data_proof_options_json, key_json)?;
    Ok(CString::new(vp_string)?.into_raw())
}
#[no_mangle]
/// Issue a Verifiable Presentation for [DIDAuth](https://w3c-ccg.github.io/vp-request-spec/#did-authentication-request). Input parameters are the holder URI as a C string, and JSON C strings for the linked data proof options and the JWK for signing. On success,
/// a newly-issued verifiable presentation is returned as a newly-allocated C string. The
/// returned string should be freed using [`didkit_free_string`]. On failure, `NULL` is returned, and the
/// error message can be retrieved using [`didkit_error_message`].
pub extern "C" fn didkit_did_auth(
    holder: *const c_char,
    linked_data_proof_options_json: *const c_char,
    key_json: *const c_char,
) -> *const c_char {
    ccchar_or_error(did_auth(holder, linked_data_proof_options_json, key_json))
}

// Verify Presentation
fn verify_presentation(
    presentation_json_ptr: *const c_char,
    linked_data_proof_options_json_ptr: *const c_char,
) -> Result<*const c_char, Error> {
    let presentation_json = unsafe { CStr::from_ptr(presentation_json_ptr) }.to_str()?;
    let linked_data_proof_options_json =
        unsafe { CStr::from_ptr(linked_data_proof_options_json_ptr) }.to_str()?;
    let result_json =
        crate::verify_presentation(presentation_json, linked_data_proof_options_json)?;
    Ok(CString::new(result_json)?.into_raw())
}
#[no_mangle]
/// Verify a Verifiable Presentation. Arguments are a C string containing the Verifiable
/// Presentation to verify, and a C string containing a JSON object for the linked data proof
/// options for verification. The return value is a newly-allocated C string containing a JSON
/// object for the verification result, or `NULL` in case of certain errors. On successful
/// verification, the verification result JSON object contains a "errors" property whose value is
/// an empty array. If verification fails, either `NULL` is returned and the error can be retrieved
/// using [`didkit_error_message`], or a verification result JSON object is returned with an "errors"
/// array containing information about the verification error(s) encountered. A string returned
/// from this function should be freed using [`didkit_free_string`].
pub extern "C" fn didkit_vc_verify_presentation(
    presentation_json: *const c_char,
    linked_data_proof_options_json: *const c_char,
) -> *const c_char {
    ccchar_or_error(verify_presentation(
        presentation_json,
        linked_data_proof_options_json,
    ))
}

// Resolve DID
fn resolve_did(
    did_ptr: *const c_char,
    input_metadata_json_ptr: *const c_char,
) -> Result<*const c_char, Error> {
    let did = unsafe { CStr::from_ptr(did_ptr) }.to_str()?;
    let input_metadata_json = if input_metadata_json_ptr.is_null() {
        "{}"
    } else {
        unsafe { CStr::from_ptr(input_metadata_json_ptr) }.to_str()?
    };
    let result_string = crate::resolve_did(did, input_metadata_json)?;
    Ok(CString::new(result_string)?.into_raw())
}

#[no_mangle]
/// Resolve a DID to a DID Document. Arguments are a C string containing the DID to resolve, and a
/// C string containing a JSON object for resolution input metadata. The return value on success is
/// a newly-allocated C string containing either the resolved DID document or a DID resolution
/// result JSON object. On error, `NULL` is returned, and the error can be retrieved using
/// [`didkit_error_message`].
pub extern "C" fn didkit_did_resolve(
    did: *const c_char,
    input_metadata_json: *const c_char,
) -> *const c_char {
    ccchar_or_error(resolve_did(did, input_metadata_json))
}

// Dereference DID URL
fn dereference_did_url(
    did_url_ptr: *const c_char,
    input_metadata_json_ptr: *const c_char,
) -> Result<*const c_char, Error> {
    let did_url = unsafe { CStr::from_ptr(did_url_ptr) }.to_str()?;
    let input_metadata_json = if input_metadata_json_ptr.is_null() {
        "{}"
    } else {
        unsafe { CStr::from_ptr(input_metadata_json_ptr) }.to_str()?
    };
    let result_string = crate::dereference_did_url(did_url, input_metadata_json)?;
    Ok(CString::new(result_string)?.into_raw())
}

#[no_mangle]
/// Resolve a DID to a DID Document. Arguments are a C string containing the DID URL to dereference, and a
/// C string containing a JSON object for dereferencing input metadata. The return value on success is
/// a newly-allocated C string containing either a resolved resource or a DID resolution
/// result JSON object. On error, `NULL` is returned, and the error can be retrieved using
/// [`didkit_error_message`].
pub extern "C" fn didkit_did_url_dereference(
    did_url: *const c_char,
    input_metadata_json: *const c_char,
) -> *const c_char {
    ccchar_or_error(dereference_did_url(did_url, input_metadata_json))
}

#[no_mangle]
/// Free a C string that has been dynamically allocated by DIDKit. This should be used for strings
/// returned from most DIDKit C functions, per their respective documentation.
pub extern "C" fn didkit_free_string(string: *const c_char) {
    if string.is_null() {
        return;
    }
    unsafe {
        CString::from_raw(string as *mut c_char);
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
