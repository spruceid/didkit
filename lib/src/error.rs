use std::ffi::CString;
use std::fmt;
use std::os::raw::{c_char, c_int};
use std::ptr;

static UNKNOWN_ERROR: &str = "Unable to create error string\0";

use std::cell::RefCell;
thread_local! {
    pub static LAST_ERROR: RefCell<Option<(i32, CString)>> = RefCell::new(None);
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    VC(#[from] ssi::vc::Error),
    #[error(transparent)]
    Zcap(#[from] ssi::zcap::Error),
    #[error(transparent)]
    JWK(#[from] ssi::jwk::Error),
    #[error(transparent)]
    Null(#[from] std::ffi::NulError),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Borrow(#[from] std::cell::BorrowError),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    DecodeHexError(#[from] crate::util::DecodeHexError),
    #[error("Unable to generate DID")]
    UnableToGenerateDID,
    #[error("Unknown DID method")]
    UnknownDIDMethod,
    #[error("Unable to get verification method")]
    UnableToGetVerificationMethod,
    #[error("Unknown proof format: {0}")]
    UnknownProofFormat(String),

    #[doc(hidden)]
    #[error("")]
    __Nonexhaustive,
}

impl Error {
    pub fn stash(self) {
        LAST_ERROR.with(|stash| {
            stash.replace(Some((
                self.get_code(),
                CString::new(self.to_string()).unwrap(),
            )))
        });
    }

    fn get_code(&self) -> c_int {
        // TODO: try to give each individual error its own number
        match self {
            Error::VC(_) => 1,
            Error::Null(_) => 2,
            Error::Utf8(_) => 3,
            Error::JWK(_) => 4,
            Error::Zcap(_) => 5,
            _ => -1,
        }
    }
}

#[no_mangle]
/// Retrieve a human-readable description of the most recent error encountered by a DIDKit C
/// function. The returned string is valid until the next call to a DIDKit function in the current
/// thread, and should not be mutated or freed. If there has not been any error, `NULL` is returned.
pub extern "C" fn didkit_error_message() -> *const c_char {
    LAST_ERROR.with(|error| match error.try_borrow() {
        Ok(maybe_err_ref) => match &*maybe_err_ref {
            Some(err) => err.1.as_ptr() as *const c_char,
            None => ptr::null(),
        },
        Err(_) => UNKNOWN_ERROR.as_ptr() as *const c_char,
    })
}

#[no_mangle]
/// Retrieve a numeric code for the most recent error encountered by a DIDKit C function. If there
/// has not been an error, 0 is returned.
pub extern "C" fn didkit_error_code() -> c_int {
    LAST_ERROR.with(|error| match error.try_borrow() {
        Ok(maybe_err_ref) => match &*maybe_err_ref {
            Some(err) => err.0,
            None => 0,
        },
        Err(err) => Error::from(err).get_code(),
    })
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        Error::VC(ssi::vc::Error::from(err))
    }
}

impl From<ssi::ldp::Error> for Error {
    fn from(e: ssi::ldp::Error) -> Error {
        ssi::vc::Error::from(e).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors() {
        use crate::c::didkit_vc_issue_presentation;
        use std::ffi::CStr;
        let presentation = "{}\0".as_ptr() as *const c_char;
        let options = "{}\0".as_ptr() as *const c_char;
        let key = "{}\0".as_ptr() as *const c_char;
        let vp = didkit_vc_issue_presentation(presentation, options, key);
        assert_eq!(vp, ptr::null());
        let msg = unsafe { CStr::from_ptr(didkit_error_message()) }
            .to_str()
            .unwrap();
        let code = didkit_error_code();
        assert_ne!(code, 0);
        println!("code: {:?} msg: {:?}", code, msg);
    }
}
