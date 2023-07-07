use anyhow::Context;
use axum::{http::StatusCode, Extension, Json};
use didkit::{
    ssi::{ldp::Error as LdpError, vc::Error as VCError},
    ContextLoader, JWTOrLDPOptions, ProofFormat, VerifiablePresentation, VerificationResult,
    DID_METHODS,
};
use serde::{Deserialize, Serialize};

use crate::{error::Error, keys::pick_key, KeyMap};

// TODO move to ssi
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum PresentationOrJWT {
    VP(VerifiablePresentation),
    Jwt(String),
}

#[derive(Deserialize)]
pub struct IssueRequest {
    pub presentation: VerifiablePresentation,
    pub options: Option<JWTOrLDPOptions>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueResponse {
    pub verifiable_presentation: PresentationOrJWT,
}

pub async fn issue(
    Extension(keys): Extension<KeyMap>,
    Json(req): Json<IssueRequest>,
) -> Result<(StatusCode, Json<IssueResponse>), Error> {
    let mut presentation = req.presentation;
    let options = req.options.unwrap_or_default();
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ContextLoader::default();
    let key = match pick_key(
        &keys,
        &presentation.holder.clone().map(String::from),
        &options.ldp_options,
        resolver,
    )
    .await
    {
        Some(key) => key,
        None => return Err((StatusCode::NOT_FOUND, "Missing key".to_string()).into()),
    };
    if let Err(e) = presentation.validate_unsigned() {
        return Err((StatusCode::BAD_REQUEST, e.to_string()).into());
    }
    let res = match proof_format {
        ProofFormat::JWT => PresentationOrJWT::Jwt(
            presentation
                .generate_jwt(Some(key), &options.ldp_options, resolver)
                .await
                .context("Failed to issue JWT VC")?,
        ),
        ProofFormat::LDP => {
            let proof = match presentation
                .generate_proof(key, &options.ldp_options, resolver, &mut context_loader)
                .await
            {
                Ok(p) => p,
                Err(VCError::LDP(LdpError::ToRdfError(e))) => {
                    return Err(
                        (StatusCode::BAD_REQUEST, LdpError::ToRdfError(e).to_string()).into(),
                    )
                }
                e => e.context("Faield to generate proof")?,
            };
            presentation.add_proof(proof);
            PresentationOrJWT::VP(presentation)
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
    pub verifiable_presentation: PresentationOrJWT,
    pub options: Option<JWTOrLDPOptions>,
}

pub async fn verify(Json(req): Json<VerifyRequest>) -> Result<Json<VerificationResult>, Error> {
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ContextLoader::default();
    let options = req.options.unwrap_or_default();
    let ldp_options = options.ldp_options;
    let res = match (options.proof_format, req.verifiable_presentation) {
        (Some(ProofFormat::LDP), PresentationOrJWT::VP(vp)) | (None, PresentationOrJWT::VP(vp)) => {
            if let Err(e) = vp.validate() {
                return Err((StatusCode::BAD_REQUEST, e.to_string()).into());
            }
            vp.verify(Some(ldp_options), resolver, &mut context_loader)
                .await
        }
        (Some(ProofFormat::JWT), PresentationOrJWT::Jwt(vc_jwt))
        | (None, PresentationOrJWT::Jwt(vc_jwt)) => {
            VerifiablePresentation::verify_jwt(
                &vc_jwt,
                Some(ldp_options),
                resolver,
                &mut context_loader,
            )
            .await
        }
        (Some(proof_format), vc) => {
            let err_msg = format!(
                "Credential/proof format mismatch. Proof format: {}, presentation format: {}",
                proof_format,
                match vc {
                    PresentationOrJWT::Jwt(_) => "JWT".to_string(),
                    PresentationOrJWT::VP(_) => "LDP".to_string(),
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
