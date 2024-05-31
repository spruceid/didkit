use axum::{http::StatusCode, Extension, Json};
use didkit::{
    ssi::{
        claims::{
            data_integrity::{AnyInputContext, AnySuite, CryptographicSuite},
            vc::ToJwtClaims,
            Credential, JsonCredential, JsonCredentialOrJws, ValidationEnvironment,
            VerifiableClaims,
        },
        dids::{AnyDidMethod, VerificationMethodDIDResolver},
        prelude::JWSPayload,
        verification_methods::{
            AnyMethod, MaybeJwkVerificationMethod, ReferenceOrOwned, ReferenceOrOwnedRef,
            VerificationMethodResolver,
        },
    },
    JWTOrLDPOptions, ProofFormat, VerificationOptions,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    keys::KeyMapSigner,
    utils::{Check, CustomErrorJson, VerificationResult},
    KeyMap,
};

#[derive(Deserialize)]
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
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());

    req.options.ldp_options.verification_method = Some(ReferenceOrOwned::Reference(
        req.credential.issuer.id().to_owned().into_iri(),
    ));

    let method = resolver
        .resolve_verification_method(
            Some(req.credential.issuer.id().as_iri()),
            Some(ReferenceOrOwnedRef::Reference(
                req.credential.issuer.id().as_iri(),
            )),
        )
        .await?;

    let public_jwk = method.try_to_jwk().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Could not get any verification method for issuer DID".to_string(),
    ))?;

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
            let suite = AnySuite::pick(
                &public_jwk,
                req.options.ldp_options.verification_method.as_ref(),
            )
            .unwrap();

            let signer = KeyMapSigner(keys).into_local();
            let vc = suite
                .sign(
                    req.credential,
                    AnyInputContext::default(),
                    resolver,
                    signer,
                    req.options.ldp_options,
                )
                .await
                .unwrap();

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
