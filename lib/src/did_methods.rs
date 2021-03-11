use did_ethr::DIDEthr;
use did_key::DIDKey;
use did_sol::DIDSol;
use did_tezos::DIDTz;
use did_web::DIDWeb;
use ssi::did::DIDMethods;

lazy_static! {
    static ref DIDTZ: DIDTz = DIDTz::default();
    pub static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(&DIDKey);
        methods.insert(&*DIDTZ);
        methods.insert(&DIDEthr);
        methods.insert(&DIDSol);
        methods.insert(&DIDWeb);
        methods
    };
}
