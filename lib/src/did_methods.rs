use did_ethr::DIDEthr;
use did_method_key::DIDKey;
use did_onion::DIDOnion;
use did_pkh::DIDPKH;
use did_sol::DIDSol;
use did_tz::DIDTz;
use did_web::DIDWeb;
use did_webkey::DIDWebKey;
use ssi::did::DIDMethods;

lazy_static! {
    static ref DIDTZ: DIDTz = DIDTz::default();
    static ref DIDONION: DIDOnion = DIDOnion::default();
    pub static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(&DIDKey);
        methods.insert(&*DIDTZ);
        methods.insert(&DIDEthr);
        methods.insert(&DIDSol);
        methods.insert(&DIDWeb);
        methods.insert(&DIDWebKey);
        methods.insert(&DIDPKH);
        methods.insert(&*DIDONION);
        methods
    };
}
