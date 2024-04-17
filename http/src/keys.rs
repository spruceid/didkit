use std::collections::HashMap;

use didkit::ssi::{
    claims::data_integrity::ProofConfiguration,
    dids::{AnyDidMethod, VerificationMethodDIDResolver},
    verification_methods::{AnyMethod, ReferenceOrOwned, VerificationMethodResolver},
    JWK,
};
use tracing::error;

pub type KeyMap = HashMap<JWK, JWK>;

pub async fn pick_key<'a>(
    keys: &'a KeyMap,
    issuer: ReferenceOrOwned<AnyMethod>,
    options: &Option<ProofConfiguration<AnyMethod>>,
    did_resolver: AnyDidMethod,
) -> Option<&'a JWK> {
    if keys.len() <= 1 {
        return keys.values().next();
    }
    let public_key = match (issuer, options.clone().map(|o| o.verification_method)) {
        (_, Some(vm)) | (vm, None) => {
            match VerificationMethodDIDResolver::new(did_resolver)
                .resolve_verification_method(None, Some(vm.borrowed()))
                .await
            {
                Err(err) => {
                    error!("{err:?}");
                    return None;
                }
                Ok(key) => match key.try_to_jwk() {
                    Some(k) => k.into_owned(),
                    None => {
                        error!("No JWK in VM");
                        return None;
                    }
                },
            }
        }
    };
    keys.get(&public_key)
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
