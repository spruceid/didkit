use did_ethr::DIDEthr;
use did_method_key::DIDKey;
use did_onion::DIDOnion;
use did_pkh::DIDPKH;
// use did_sol::DIDSol;
use did_ion::DIDION;
use did_jwk::DIDJWK;
use did_tz::DIDTz;
use did_web::DIDWeb;
use did_webkey::DIDWebKey;
use ssi::did::DIDMethods;
use std::env::VarError;

lazy_static! {
    static ref DIDTZ: DIDTz = DIDTz::default();
    static ref DIDONION: DIDOnion = {
        let mut onion = DIDOnion::default();
        if let Some(url) = match std::env::var("DID_ONION_PROXY_URL") {
            Ok(url) => Some(url),
            Err(VarError::NotPresent) => None,
            Err(VarError::NotUnicode(err)) => {
                eprintln!("Unable to parse DID_ONION_PROXY_URL: {:?}", err);
                None
            }
        } {
            onion.proxy_url = url;
        }
        onion
    };
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
        methods.insert(Box::new(DIDKey));
        methods.insert(Box::new(DIDTZ.clone()));
        methods.insert(Box::new(DIDEthr));
        // methods.insert(&DIDSol);
        methods.insert(Box::new(DIDWeb));
        methods.insert(Box::new(DIDWebKey));
        methods.insert(Box::new(DIDPKH));
        methods.insert(Box::new(DIDONION.clone()));
        methods.insert(Box::new(ION.clone()));
        methods.insert(Box::new(DIDJWK));
        methods
    };
}
