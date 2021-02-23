use did_ethr::DIDEthr;
use did_key::DIDKey;
use did_tezos::DIDTz;
#[cfg(feature = "did-web")]
use did_web::DIDWeb;
use ssi::did::DIDMethods;

lazy_static! {
    pub static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(&DIDKey);
        methods.insert(&DIDTz);
        methods.insert(&DIDEthr);
        #[cfg(feature = "did-web")]
        methods.insert(&DIDWeb);
        methods
    };
}
