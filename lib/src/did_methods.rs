use std::env::VarError;

use lazy_static::lazy_static;
use ssi::dids::{AnyDidMethod, DIDTz, DIDION};

lazy_static! {
    static ref DID_TZ: DIDTz = DIDTz::default();
    static ref DID_ION: DIDION = DIDION::new(match std::env::var("DID_ION_API_URL") {
        Ok(string) => match string.parse() {
            Ok(url) => Some(url),
            Err(err) => {
                eprintln!("Unable to parse DID_ION_API_URL: {:?}", err);
                None
            }
        },
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(err)) => {
            eprintln!("Unable to parse DID_ION_API_URL: {:?}", err);
            None
        }
    });
    pub static ref DID_METHODS: AnyDidMethod = AnyDidMethod::new(DID_ION.clone(), DID_TZ.clone());
}
