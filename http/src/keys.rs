use std::collections::HashMap;

use didkit::{resolve_key, DIDResolver, LinkedDataProofOptions, Source, DID_METHODS, JWK};

pub type KeyMap = HashMap<JWK, JWK>;

pub async fn pick_key<'a>(
    keys: &'a KeyMap,
    issuer: &Option<String>,
    options: &LinkedDataProofOptions,
    did_resolver: &dyn DIDResolver,
) -> Option<&'a JWK> {
    if keys.len() <= 1 {
        return keys.values().next();
    }
    let public_key = match (issuer, options.verification_method.clone()) {
        (_, Some(vm)) => {
            match resolve_key(&vm.to_string(), did_resolver).await {
                Err(_err) => {
                    // TODO: return error
                    return None;
                }
                Ok(key) => key,
            }
        }
        (Some(issuer), None) => {
            let method = match DID_METHODS.get_method(issuer) {
                Ok(m) => m,
                Err(_) => {
                    return None;
                }
            };
            for jwk in keys.keys() {
                let did = match method.generate(&Source::Key(jwk)) {
                    Some(d) => d,
                    None => continue,
                };
                if &did == issuer {
                    return keys.get(jwk);
                }
            }
            return None;
        }
        (None, None) => return keys.values().next(),
    };
    keys.get(&public_key)
}

#[cfg(test)]
mod test {
    use didkit::URI;

    use crate::test::default_keys;

    use super::*;

    #[tokio::test]
    async fn pick_key_only_issuer() {
        let keys = default_keys();

        let p256_did = "did:key:zDnaej4NHTz2DtpMByubtLGzZfEjYor4ffJWLuW2eJ4KkZ3r2".to_string();
        let ed25519_did = "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD".to_string();

        let options = LinkedDataProofOptions::default();

        let key1 = pick_key(&keys, &Some(p256_did), &options, DID_METHODS.to_resolver())
            .await
            .unwrap();
        let key2 = pick_key(
            &keys,
            &Some(ed25519_did),
            &options,
            DID_METHODS.to_resolver(),
        )
        .await
        .unwrap();

        assert_ne!(key1, key2);
    }

    #[tokio::test]
    async fn pick_key_ldp_options() {
        let keys = default_keys();

        let p256_did = "did:key:zDnaej4NHTz2DtpMByubtLGzZfEjYor4ffJWLuW2eJ4KkZ3r2".to_string();

        let options = LinkedDataProofOptions {
        verification_method: Some(URI::String("did:key:zDnaej4NHTz2DtpMByubtLGzZfEjYor4ffJWLuW2eJ4KkZ3r2#zDnaej4NHTz2DtpMByubtLGzZfEjYor4ffJWLuW2eJ4KkZ3r2".to_string())),
        ..Default::default()
    };

        let key1 = pick_key(
            &keys,
            &Some(p256_did.clone()),
            &options,
            DID_METHODS.to_resolver(),
        )
        .await
        .unwrap();
        let key2 = pick_key(
            &keys,
            &Some(p256_did),
            &LinkedDataProofOptions::default(),
            DID_METHODS.to_resolver(),
        )
        .await
        .unwrap();

        assert_eq!(key1, key2);
    }
}
