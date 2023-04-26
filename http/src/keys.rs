use std::collections::HashMap;

use didkit::{resolve_key, DIDResolver, LinkedDataProofOptions, JWK};

pub type KeyMap = HashMap<JWK, JWK>;

pub async fn pick_key<'a>(
    keys: &'a KeyMap,
    options: &LinkedDataProofOptions,
    did_resolver: &dyn DIDResolver,
) -> Option<&'a JWK> {
    if keys.len() <= 1 {
        return keys.values().next();
    }
    let vm = match options.verification_method {
        Some(ref verification_method) => verification_method.to_string(),
        None => return keys.values().next(),
    };
    let public_key = match resolve_key(&vm, did_resolver).await {
        Err(_err) => {
            // TODO: return error
            return None;
        }
        Ok(key) => key,
    };
    keys.get(&public_key)
}
