use std::collections::HashMap;

use didkit::ssi::{
    verification_methods::{LocalSigner, MaybeJwkVerificationMethod, Signer},
    JWK,
};

pub type KeyMap = HashMap<JWK, JWK>;

pub struct KeyMapSigner(pub KeyMap);

impl KeyMapSigner {
    pub fn into_local(self) -> LocalSigner<Self> {
        LocalSigner(self)
    }
}

impl<M: MaybeJwkVerificationMethod> Signer<M> for KeyMapSigner {
    type MessageSigner = JWK;

    async fn for_method(&self, method: std::borrow::Cow<'_, M>) -> Option<Self::MessageSigner> {
        let public_jwk = method.try_to_jwk()?;
        self.0.get(&public_jwk).cloned()
    }
}

// #[cfg(test)]
// mod test {
//     use didkit::URI;
//
//     use crate::test::default_keys;
//
//     use super::*;
//
//     #[tokio::test]
//     async fn pick_key_only_issuer() {
//         let keys = default_keys();
//
//         let p256_did = "did:key:zDnaej4NHTz2DtpMByubtLGzZfEjYor4ffJWLuW2eJ4KkZ3r2".to_string();
//         let ed25519_did = "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD".to_string();
//
//         let options = LinkedDataProofOptions::default();
//
//         let key1 = pick_key(&keys, &Some(p256_did), &options, DID_METHODS.to_resolver())
//             .await
//             .unwrap();
//         let key2 = pick_key(
//             &keys,
//             &Some(ed25519_did),
//             &options,
//             DID_METHODS.to_resolver(),
//         )
//         .await
//         .unwrap();
//
//         assert_ne!(key1, key2);
//     }
//
//     #[tokio::test]
//     async fn pick_key_ldp_options() {
//         let keys = default_keys();
//
//         let p256_did = "did:key:zDnaej4NHTz2DtpMByubtLGzZfEjYor4ffJWLuW2eJ4KkZ3r2".to_string();
//
//         let options = ProofConfiguration<AnyMethod> {
//         verification_method: Some(iri!("did:key:zDnaej4NHTz2DtpMByubtLGzZfEjYor4ffJWLuW2eJ4KkZ3r2#zDnaej4NHTz2DtpMByubtLGzZfEjYor4ffJWLuW2eJ4KkZ3r2")),
//         ..Default::default()
//     };
//
//         let key1 = pick_key(
//             &keys,
//             &Some(p256_did.clone()),
//             &options,
//             DID_METHODS.to_resolver(),
//         )
//         .await
//         .unwrap();
//         let key2 = pick_key(
//             &keys,
//             &Some(p256_did),
//             &LinkedDataProofOptions::default(),
//             DID_METHODS.to_resolver(),
//         )
//         .await
//         .unwrap();
//
//         assert_eq!(key1, key2);
//     }
// }
