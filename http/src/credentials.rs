use std::borrow::Cow;

use anyhow::Context;
use axum::{http::StatusCode, Extension, Json};
use didkit::{
    ssi::{
        claims::{
            data_integrity::{AnyInputContext, CryptographicSuite},
            vc::ToJwtClaims,
            Credential, JsonCredential, JsonCredentialOrJws, ValidationEnvironment,
            VerifiableClaims,
        },
        dids::{AnyDidMethod, DIDResolver, VerificationMethodDIDResolver, DID},
        prelude::JWSPayload,
        verification_methods::{
            AnyMethod, GenericVerificationMethod, MaybeJwkVerificationMethod, ReferenceOrOwned,
            VerificationMethodResolver,
        },
        xsd_types::DateTime,
    },
    JWTOrLDPOptions, ProofFormat, VerificationOptions,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    error::Error,
    keys::KeyMapSigner,
    utils::{self, Check, CustomErrorJson, VerificationResult},
    KeyMap,
};

#[derive(Deserialize, Debug)]
pub struct IssueRequest {
    pub credential: JsonCredential,
    pub options: JWTOrLDPOptions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueResponse {
    pub verifiable_credential: JsonCredentialOrJws,
}

#[axum::debug_handler]
pub async fn issue(
    Extension(keys): Extension<KeyMap>,
    CustomErrorJson(mut req): CustomErrorJson<IssueRequest>,
) -> Result<(StatusCode, Json<IssueResponse>), Error> {
    info!("{req:?}");

    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());

    // Find an appropriate verification method.
    let method = match &req.options.ldp_options.input_options.verification_method {
        Some(method) => {
            resolver
                .resolve_verification_method(
                    Some(req.credential.issuer.id().as_iri()),
                    Some(method.borrowed()),
                )
                .await?
        }
        None => {
            let did = DID::new(req.credential.issuer.id()).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not get any verification method for issuer URI".to_string(),
                )
            })?;

            let output = resolver.resolve(did).await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not fetch issuer DID document".to_string(),
                )
            })?;

            let method = output
                .document
                .into_document()
                .into_any_verification_method()
                .ok_or((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not get any verification method for issuer DID document",
                ))?;

            req.options.ldp_options.input_options.verification_method =
                Some(ReferenceOrOwned::Reference(method.id.clone().into_iri()));

            Cow::Owned(GenericVerificationMethod::from(method).try_into()?)
        }
    };

    let public_jwk = method.try_to_jwk().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Could not get any verification method for issuer DID".to_string(),
    ))?;

    if req.credential.issuance_date.is_none() {
        req.credential.issuance_date = Some(DateTime::now_ms());
    }
    if req.options.ldp_options.type_ == Some("DataIntegrityProof".to_string()) {
        if req.options.ldp_options.cryptosuite.is_none() {
            req.options.ldp_options.cryptosuite =
                Some(utils::pick_from_jwk(&public_jwk).context("Could not pick cryptosuite")?)
        }
        // TODO check if main context is v1 and data-integrity context isn't already present
        req.options
            .ldp_options
            .input_options
            .extra_properties
            .insert(
                "@context".to_string(),
                "https://w3id.org/security/data-integrity/v1".into(),
            );
    }

    if let Err(err) = req
        .credential
        .validate_credential(&ValidationEnvironment::default())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Credential not valid, {err:?}"),
        )
            .into());
    }

    let res = match req.options.proof_format {
        ProofFormat::JWT => JsonCredentialOrJws::Jws(
            req.credential
                .to_jwt_claims()
                .unwrap()
                .sign(&public_jwk)
                .await
                .unwrap(),
        ),
        ProofFormat::LDP => {
            let suite = req.options.ldp_options.select_suite(&public_jwk).unwrap();

            let signer = KeyMapSigner(keys).into_local();
            let vc = suite
                .sign(
                    req.credential,
                    AnyInputContext::default(),
                    resolver,
                    signer,
                    req.options.ldp_options.input_options,
                )
                .await
                .context("Failed to sign VC")?;

            // serde_json::to_value(&vc).expect("Could not serialize VC")
            JsonCredentialOrJws::Credential(vc.unprepare())
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

    #[serde(default)]
    pub options: VerificationOptions,
}

pub async fn verify(
    CustomErrorJson(req): CustomErrorJson<VerifyRequest>,
) -> Result<Json<VerificationResult>, Error> {
    let resolver = VerificationMethodDIDResolver::new(AnyDidMethod::default());
    let res = match (req.options.proof_format, req.verifiable_credential) {
        (Some(ProofFormat::LDP) | None, JsonCredentialOrJws::Credential(vc)) => {
            match vc.into_verifiable().await {
                Ok(vc) => match vc.verify(&resolver).await {
                    Ok(Ok(())) => VerificationResult {
                        checks: vec![Check::Proof],
                        warnings: vec![],
                        errors: vec![],
                    },
                    Ok(Err(err)) => VerificationResult {
                        checks: vec![Check::Proof],
                        warnings: vec![],
                        errors: vec![err.to_string()],
                    },
                    Err(err) => VerificationResult {
                        checks: vec![Check::Proof],
                        warnings: vec![],
                        errors: vec![err.to_string()],
                    },
                },
                Err(err) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![err.to_string()],
                },
            }
        }
        (Some(ProofFormat::JWT) | None, JsonCredentialOrJws::Jws(vc_jwt)) => {
            // TODO: only the JWS is verified this way. We must also validate the inner VC.
            match vc_jwt.verify(&resolver).await {
                Ok(Ok(())) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![],
                },
                Ok(Err(err)) => VerificationResult {
                    checks: vec![Check::Proof],
                    warnings: vec![],
                    errors: vec![err.to_string()],
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
    use test_log::test;

    use crate::test::default_keys;

    use super::*;

    #[test(tokio::test)]
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

    #[test(tokio::test)]
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

    #[test]
    fn deserialize_body_issuer_test_suite() {
        let _: IssueRequest = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "type": [
              "VerifiableCredential"
            ],
            "credentialSubject": {
              "id": "did:key:z6MkhTNL7i2etLerDK8Acz5t528giE5KA4p75T6ka1E1D74r"
            },
            "issuanceDate": "2024-06-01T09:09:48Z",
            "id": "urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f",
            "issuer": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD"
          },
          "options": {
            "type": "Ed25519Signature2020"
          }
        }
        ))
        .unwrap();
    }

    #[test(tokio::test)]
    async fn validate_valid_vc_verifier_test_suite() {
        let req = serde_json::from_value(json!({
          "verifiableCredential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": "urn:uuid:0c71c76a-5dca-4537-a86d-7851b8f85c25",
            "type": [
              "VerifiableCredential"
            ],
            "credentialSubject": {
              "id": "did:key:z6MkhTNL7i2etLerDK8Acz5t528giE5KA4p75T6ka1E1D74r"
            },
            "issuer": "did:key:z6MkgND5U5Kedizov5nxeh2ZCVUTDRSmAfbNqPhzCq8b72Ra",
            "issuanceDate": "2024-06-01T09:34:12.834Z",
            "proof": {
              "type": "Ed25519Signature2020",
              "proofPurpose": "assertionMethod",
              "proofValue": "zB6pd365FSMVZbkn51nhEtLCyuxLj5qGFaZi6uv1dweLUiR1qvCqM1cqaAFMgjyB5ZATvU2brPDn6z6XwxoFyeHD",
              "verificationMethod": "did:key:z6MkgND5U5Kedizov5nxeh2ZCVUTDRSmAfbNqPhzCq8b72Ra#z6MkgND5U5Kedizov5nxeh2ZCVUTDRSmAfbNqPhzCq8b72Ra",
              "created": "2024-06-01T09:34:12.834Z"
            }
          },
          "options": {
            "checks": [
              "proof"
            ]
          }
        })).unwrap();
        let _ = verify(CustomErrorJson(req)).await.unwrap();
    }

    #[test(tokio::test)]
    async fn issue_valid_di_eddsa_test_suite() {
        let keys = default_keys();
        let req = serde_json::from_value(json!({
          "credential": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "urn:uuid:991721d2-2336-4979-aa10-1709061b7261",
            "type": [
              "VerifiableCredential"
            ],
            "issuer": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
            "issuanceDate": "2020-03-16T22:37:26.544Z",
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
