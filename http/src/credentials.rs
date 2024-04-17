use axum::{http::StatusCode, Extension, Json};
use didkit::{
    ssi::{
        claims::{
            data_integrity::{
                AnyInputContext, AnySuite, CryptographicSuiteInput, ProofConfiguration,
            },
            vc::any_credential_from_json_slice,
            Credential, JsonCredentialOrJws, ProofValidity, SpecializedJsonCredential,
        },
        dids::{AnyDidMethod, DIDBuf, DIDResolver, DIDTz, VerificationMethodDIDResolver, DIDION},
        verification_methods::{AnyJwkMethod, AnyMethod, ReferenceOrOwned, SingleSecretSigner},
    },
    JWTOrLDPOptions, ProofFormat,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    keys::pick_key,
    utils::{Check, CustomErrorJson, VerificationResult},
    KeyMap,
};

#[derive(Deserialize)]
pub struct IssueRequest {
    pub credential: SpecializedJsonCredential,
    pub options: Option<JWTOrLDPOptions>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueResponse {
    pub verifiable_credential: serde_json::Value,
}

pub async fn issue(
    Extension(keys): Extension<KeyMap>,
    CustomErrorJson(req): CustomErrorJson<IssueRequest>,
) -> Result<(StatusCode, Json<IssueResponse>), Error> {
    let credential = req.credential;
    let options = req.options;
    let proof_format = options.clone().map(|o| o.proof_format).unwrap_or_default();
    let resolver = AnyDidMethod::new(DIDION::new(None), DIDTz::default());
    let vm_resolver =
        VerificationMethodDIDResolver::new(AnyDidMethod::new(DIDION::new(None), DIDTz::default()));
    let issuer = credential.issuer().clone();
    let issuer_did = DIDBuf::from_string(issuer.id().to_string()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Issuer ID is not a DID: {e}"),
        )
    })?;
    let issuer_verification_method: ReferenceOrOwned<AnyMethod> = resolver
        .resolve_into_any_verification_method(&issuer_did)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not resolve issuer DID: {e}"),
            )
        })?
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not get any verification method for issuer DID".to_string(),
        ))?
        .id
        .into_iri()
        .into();
    let key = match pick_key(
        &keys,
        issuer_verification_method.clone(),
        &options.clone().map(|o| o.ldp_options),
        resolver,
    )
    .await
    {
        Some(key) => key,
        None => return Err((StatusCode::NOT_FOUND, "Missing key".to_string()).into()),
    };
    let verification_method = options
        .clone()
        .map(|o| o.ldp_options.verification_method)
        .unwrap_or(issuer_verification_method);
    let signer = SingleSecretSigner::new(key.clone());
    if !credential.is_valid_credential() {
        return Err((StatusCode::BAD_REQUEST, "Invalid credential".to_string()).into());
    }
    let res = match proof_format.unwrap_or(ProofFormat::LDP) {
        ProofFormat::JWT => {
            let jwt = credential
                .to_jwt_claims()
                .unwrap()
                .sign(&verification_method, &vm_resolver, &signer)
                .await
                .unwrap();
            serde_json::Value::String(jwt.to_string())
        }
        ProofFormat::LDP => {
            let params = ProofConfiguration::from_method_and_options(
                verification_method,
                Default::default(),
            );

            let suite = AnySuite::pick(&key, Some(&params.verification_method)).unwrap();
            let vc = suite
                .sign(
                    credential,
                    AnyInputContext::default(),
                    &vm_resolver,
                    &signer,
                    params,
                )
                .await
                .unwrap();
            serde_json::to_value(&vc).expect("Could not serialize VC")
        }
        _ => return Err((StatusCode::BAD_REQUEST, "Unknown proof format".to_string()).into()),
    };
    Ok((
        StatusCode::CREATED,
        Json(IssueResponse {
            verifiable_credential: res,
        }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub verifiable_credential: JsonCredentialOrJws,
    pub options: Option<JWTOrLDPOptions>,
}

pub async fn verify(
    CustomErrorJson(req): CustomErrorJson<VerifyRequest>,
) -> Result<Json<VerificationResult>, Error> {
    let resolver = AnyDidMethod::new(DIDION::new(None), DIDTz::default());
    let vm_resolver = VerificationMethodDIDResolver::new(resolver);
    let options = req.options;
    let res = match (
        options.clone().and_then(|o| o.proof_format),
        req.verifiable_credential,
    ) {
        (Some(ProofFormat::LDP), JsonCredentialOrJws::Credential(vc))
        | (None, JsonCredentialOrJws::Credential(vc)) => {
            if !vc.is_valid_credential() {
                return Err((StatusCode::BAD_REQUEST, "Credential not valid".to_string()).into());
            }
            let vc = any_credential_from_json_slice(
                &serde_json::to_vec(&vc).expect("Could not serialize VC to bytes"),
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Could not build verifiable: {e}"),
                )
            })?;
            match vc.verify(&vm_resolver).await {
                Ok(ProofValidity::Valid) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![],
                },
                Ok(ProofValidity::Invalid) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec!["Failed verification".to_string()],
                },
                Err(err) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![err.to_string()],
                },
            }
        }
        (Some(ProofFormat::JWT), JsonCredentialOrJws::Jws(vc_jwt))
        | (None, JsonCredentialOrJws::Jws(vc_jwt)) => {
            match vc_jwt.verify::<AnyJwkMethod>(&vm_resolver).await {
                Ok(true) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![],
                },
                Ok(false) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec!["Failed verification".to_string()],
                },
                Err(err) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![err.to_string()],
                },
            }
        }
        (Some(proof_format), vc) => {
            let err_msg = format!(
                "Credential/proof format mismatch. Proof format: {}, credential format: {}",
                proof_format,
                match vc {
                    JsonCredentialOrJws::Jws(_) => "JWT".to_string(),
                    JsonCredentialOrJws::Credential(_) => "LDP".to_string(),
                }
            );
            return Err((StatusCode::BAD_REQUEST, err_msg).into());
        }
    };
    if !res.errors.is_empty() {
        return Err((StatusCode::BAD_REQUEST, format!("{:?}", res.errors)).into());
    }
    Ok(Json(res))
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::test::default_keys;

    use super::*;

    #[tokio::test]
    async fn issue_ed25519() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:040d4921-4756-447b-99ad-8d4978420e91",
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
            "credentialSubject": {
              "id": "did:key:z6MktKwz7Ge1Yxzr4JHavN33wiwa8y81QdcMRLXQsrH9T53b"
            }
          },
          "options": {
            "type": "DataIntegrityProof"
          }
        }))
        .unwrap();

        let _ = issue(Extension(keys), CustomErrorJson(req)).await.unwrap();
    }

    #[tokio::test]
    async fn issue_p256() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:040d4921-4756-447b-99ad-8d4978420e91",
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:key:zDnaej4NHTz2DtpMByubtLGzZfEjYor4ffJWLuW2eJ4KkZ3r2",
            "credentialSubject": {
              "id": "did:key:z6MktKwz7Ge1Yxzr4JHavN33wiwa8y81QdcMRLXQsrH9T53b"
            }
          },
          "options": {
            "type": "DataIntegrityProof"
          }
        }))
        .unwrap();

        let _ = issue(Extension(keys), CustomErrorJson(req)).await.unwrap();
    }
}
