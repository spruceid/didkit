use std::borrow::Cow;

use axum::{http::StatusCode, Extension, Json};
use didkit::{
    ssi::{
        claims::{
            data_integrity::{AnyInputContext, CryptographicSuite},
            vc::ToJwtClaims,
            JWSPayload, JsonPresentation, JsonPresentationOrJws, VerifiableClaims,
        },
        dids::{AnyDidMethod, DIDResolver, VerificationMethodDIDResolver, DID},
        verification_methods::{
            AnyMethod, GenericVerificationMethod, MaybeJwkVerificationMethod, ReferenceOrOwned,
            VerificationMethodResolver,
        },
    },
    JWTOrLDPOptions, ProofFormat, VerificationOptions,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    keys::KeyMapSigner,
    utils::{Check, VerificationResult},
    KeyMap,
};

#[derive(Deserialize)]
pub struct IssueRequest {
    pub presentation: JsonPresentation,
    pub options: JWTOrLDPOptions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueResponse {
    pub verifiable_presentation: JsonPresentationOrJws,
}

pub async fn issue(
    Extension(keys): Extension<KeyMap>,
    Json(mut req): Json<IssueRequest>,
) -> Result<(StatusCode, Json<IssueResponse>), Error> {
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());

    let holder = req
        .presentation
        .holder
        .as_deref()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing holder".to_string()))?;

    // Find an appropriate verification method.
    let method = match &req.options.ldp_options.input_options.verification_method {
        Some(method) => {
            resolver
                .resolve_verification_method(Some(holder.as_iri()), Some(method.borrowed()))
                .await?
        }
        None => {
            let did = DID::new(holder).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not get any verification method for holder URI".to_string(),
                )
            })?;

            let output = resolver.resolve(did).await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not fetch holder DID document".to_string(),
                )
            })?;

            let method = output
                .document
                .into_document()
                .into_any_verification_method()
                .ok_or((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not get any verification method for holder DID document",
                ))?;

            req.options.ldp_options.input_options.verification_method =
                Some(ReferenceOrOwned::Reference(method.id.clone().into_iri()));

            Cow::Owned(GenericVerificationMethod::from(method).try_into()?)
        }
    };

    let public_jwk = method.try_to_jwk().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Could not get any verification method for holder DID".to_string(),
    ))?;

    let res = match req.options.proof_format {
        ProofFormat::JWT => JsonPresentationOrJws::Jws(
            req.presentation
                .to_jwt_claims()
                .unwrap()
                .sign(&public_jwk)
                .await
                .unwrap(),
        ),
        ProofFormat::LDP => {
            let suite = req.options.ldp_options.select_suite(&public_jwk).unwrap();

            let signer = KeyMapSigner(keys).into_local();
            let vp = suite
                .sign(
                    req.presentation,
                    AnyInputContext::default(),
                    resolver,
                    signer,
                    req.options.ldp_options.input_options,
                )
                .await
                .unwrap();

            JsonPresentationOrJws::Presentation(vp.unprepare())
        }
        _ => return Err((StatusCode::BAD_REQUEST, "Unknown proof format".to_string()).into()),
    };
    Ok((
        StatusCode::CREATED,
        Json(IssueResponse {
            verifiable_presentation: res,
        }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub verifiable_presentation: JsonPresentationOrJws,

    #[serde(default)]
    pub options: VerificationOptions,
}

pub async fn verify(Json(req): Json<VerifyRequest>) -> Result<Json<VerificationResult>, Error> {
    let resolver = VerificationMethodDIDResolver::new(AnyDidMethod::default());
    let res = match (req.options.proof_format, req.verifiable_presentation) {
        (Some(ProofFormat::LDP) | None, JsonPresentationOrJws::Presentation(vp)) => {
            match vp.into_verifiable().await {
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
        (Some(ProofFormat::JWT) | None, JsonPresentationOrJws::Jws(vp_jwt)) => {
            // TODO: only the JWS is verified this way. We must also validate the inner VP.
            match vp_jwt.verify(&resolver).await {
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
                "Presentation/proof format mismatch. Proof format: {}, presentation format: {}",
                proof_format,
                match vc {
                    JsonPresentationOrJws::Jws(_) => "JWT".to_string(),
                    JsonPresentationOrJws::Presentation(_) => "LDP".to_string(),
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
