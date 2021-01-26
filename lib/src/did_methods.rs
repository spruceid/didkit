use did_key::DIDKey;
#[cfg(feature = "did-web")]
use did_web::DIDWeb;
use ssi::did::DIDMethods;

lazy_static! {
    pub static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(&DIDKey);
        #[cfg(feature = "did-web")]
        methods.insert(&DIDWeb);
        methods
    };
}
