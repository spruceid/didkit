use async_std::task::block_on;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use crate::error::Error;
use crate::LinkedDataProofOptions;
use crate::VerifiableCredential;
use crate::VerifiablePresentation;
use crate::JWK;

pub static VERSION_C: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[no_mangle]
pub extern "C" fn didkit_get_version() -> *const c_char {
    VERSION_C.as_ptr() as *const c_char
}

fn ccchar_or_error(result: Result<*const c_char, Error>) -> *const c_char {
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
    let jwk = JWK::generate_ed25519()?;
    Ok(CString::new(serde_json::to_string(&jwk)?)?.into_raw())
}
#[no_mangle]
pub extern "C" fn didkit_vc_generate_ed25519_key() -> *const c_char {
    ccchar_or_error(generate_ed25519_key())
}

// Convert JWK to did:key DID
fn key_to_did(key_json_ptr: *const c_char) -> Result<*const c_char, Error> {
    let key_json = unsafe { CStr::from_ptr(key_json_ptr) }.to_str()?;
    let key: JWK = serde_json::from_str(key_json)?;
    let did = key.to_did()?;
    Ok(CString::new(did)?.into_raw())
}
#[no_mangle]
pub extern "C" fn didkit_key_to_did(jwk: *const c_char) -> *const c_char {
    ccchar_or_error(key_to_did(jwk))
}

// Convert JWK to did:key DID URI for verificationMethod
fn key_to_verification_method(key_json_ptr: *const c_char) -> Result<*const c_char, Error> {
    let key_json = unsafe { CStr::from_ptr(key_json_ptr) }.to_str()?;
    let key: JWK = serde_json::from_str(key_json)?;
    let did = key.to_verification_method()?;
    Ok(CString::new(did)?.into_raw())
}
#[no_mangle]
pub extern "C" fn didkit_key_to_verification_method(jwk: *const c_char) -> *const c_char {
    ccchar_or_error(key_to_verification_method(jwk))
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
    let mut credential = VerifiableCredential::from_json_unsigned(credential_json)?;
    let key: JWK = serde_json::from_str(key_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(linked_data_proof_options_json)?;
    let proof = block_on(credential.generate_proof(&key, &options))?;
    credential.add_proof(proof);
    Ok(CString::new(serde_json::to_string(&credential)?)?.into_raw())
}
#[no_mangle]
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
    let credential = VerifiableCredential::from_json_unsigned(credential_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(linked_data_proof_options_json)?;
    let result = block_on(credential.verify(Some(options)));
    Ok(CString::new(serde_json::to_string(&result)?)?.into_raw())
}
#[no_mangle]
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
    let mut presentation = VerifiablePresentation::from_json_unsigned(presentation_json)?;
    let key: JWK = serde_json::from_str(key_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(linked_data_proof_options_json)?;
    let proof = block_on(presentation.generate_proof(&key, &options))?;
    presentation.add_proof(proof);
    Ok(CString::new(serde_json::to_string(&presentation)?)?.into_raw())
}
#[no_mangle]
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

// Verify Presentation
fn verify_presentation(
    presentation_json_ptr: *const c_char,
    linked_data_proof_options_json_ptr: *const c_char,
) -> Result<*const c_char, Error> {
    let presentation_json = unsafe { CStr::from_ptr(presentation_json_ptr) }.to_str()?;
    let linked_data_proof_options_json =
        unsafe { CStr::from_ptr(linked_data_proof_options_json_ptr) }.to_str()?;
    let presentation = VerifiablePresentation::from_json_unsigned(presentation_json)?;
    let options: LinkedDataProofOptions = serde_json::from_str(linked_data_proof_options_json)?;
    let result = block_on(presentation.verify(Some(options)));
    Ok(CString::new(serde_json::to_string(&result)?)?.into_raw())
}
#[no_mangle]
pub extern "C" fn didkit_vc_verify_presentation(
    presentation_json: *const c_char,
    linked_data_proof_options_json: *const c_char,
) -> *const c_char {
    ccchar_or_error(verify_presentation(
        presentation_json,
        linked_data_proof_options_json,
    ))
}

#[no_mangle]
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
