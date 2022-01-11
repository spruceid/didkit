use did_ethr::DIDEthr;
use did_method_key::DIDKey;
use did_onion::DIDOnion;
use did_pkh::DIDPKH;
// use did_sol::DIDSol;
use did_ion::DIDION;
use did_tz::DIDTz;
use did_web::DIDWeb;
use did_webkey::DIDWebKey;
use ssi::did::{DIDMethod, DIDMethods};
use std::env::VarError;

lazy_static! {
    static ref DIDTZ: DIDTz = DIDTz::default();
    static ref DIDONION: DIDOnion = DIDOnion::default();
    static ref ION: DIDION = DIDION::new(
        match std::env::var("DID_ION_API_URL") {
            Ok(string) => Some(string),
            Err(VarError::NotPresent) => None,
            Err(VarError::NotUnicode(err)) => {
                eprintln!("Unable to parse DID_ION_API_URL: {:?}", err);
                None
            }
        }
    );
    pub static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(&DIDKey);
        methods.insert(&*DIDTZ);
        methods.insert(&DIDEthr);
        // methods.insert(&DIDSol);
        methods.insert(&DIDWeb);
        methods.insert(&DIDWebKey);
        methods.insert(&DIDPKH);
        methods.insert(&*DIDONION);
        methods.insert(&*ION);
        methods
    };
}
