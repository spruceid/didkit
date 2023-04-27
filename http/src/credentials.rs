use anyhow::Context;
use axum::{http::StatusCode, Extension, Json};
use didkit::{
    ssi::ldp::Error as LdpError, ContextLoader, CredentialOrJWT, JWTOrLDPOptions, ProofFormat,
    VerifiableCredential, VerificationResult, DID_METHODS,
};
use serde::{Deserialize, Serialize};

use crate::{error::Error, keys::pick_key, utils::CustomErrorJson, KeyMap};

#[derive(Deserialize)]
pub struct IssueRequest {
    pub credential: VerifiableCredential,
    pub options: Option<JWTOrLDPOptions>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueResponse {
    pub verifiable_credential: CredentialOrJWT,
}

pub async fn issue(
    Extension(keys): Extension<KeyMap>,
    CustomErrorJson(req): CustomErrorJson<IssueRequest>,
) -> Result<(StatusCode, Json<IssueResponse>), Error> {
    let mut credential = req.credential;
    let options = req.options.unwrap_or_default();
    let proof_format = options.proof_format.unwrap_or_default();
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ContextLoader::default();
    let key = match pick_key(&keys, &options.ldp_options, resolver).await {
        Some(key) => key,
        None => return Err((StatusCode::NOT_FOUND, "Missing key".to_string()).into()),
    };
    if let Err(e) = credential.validate_unsigned() {
        return Err((StatusCode::BAD_REQUEST, e.to_string()).into());
    }
    let res = match proof_format {
        ProofFormat::JWT => CredentialOrJWT::JWT(
            credential
                .generate_jwt(Some(key), &options.ldp_options, resolver)
                .await
                .context("Failed to issue JWT VC")?,
        ),
        ProofFormat::LDP => {
            let proof = match credential
                .generate_proof(key, &options.ldp_options, resolver, &mut context_loader)
                .await
            {
                Ok(p) => p,
                Err(LdpError::ToRdfError(e)) => {
                    return Err(
                        (StatusCode::BAD_REQUEST, LdpError::ToRdfError(e).to_string()).into(),
                    )
                }
                e => e.context("Faield to generate proof")?,
            };
            credential.add_proof(proof);
            CredentialOrJWT::Credential(credential)
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
    pub verifiable_credential: CredentialOrJWT,
    pub options: Option<JWTOrLDPOptions>,
}

pub async fn verify(
    CustomErrorJson(req): CustomErrorJson<VerifyRequest>,
) -> Result<Json<VerificationResult>, Error> {
    let resolver = DID_METHODS.to_resolver();
    let mut context_loader = ContextLoader::default();
    let options = req.options.unwrap_or_default();
    let ldp_options = options.ldp_options;
    let res = match (options.proof_format, req.verifiable_credential) {
        (Some(ProofFormat::LDP), CredentialOrJWT::Credential(vc))
        | (None, CredentialOrJWT::Credential(vc)) => {
            if let Err(e) = vc.validate() {
                return Err((StatusCode::BAD_REQUEST, e.to_string()).into());
            }
            vc.verify(Some(ldp_options), resolver, &mut context_loader)
                .await
        }
        (Some(ProofFormat::JWT), CredentialOrJWT::JWT(vc_jwt))
        | (None, CredentialOrJWT::JWT(vc_jwt)) => {
            VerifiableCredential::verify_jwt(
                &vc_jwt,
                Some(ldp_options),
                resolver,
                &mut context_loader,
            )
            .await
        }
        (Some(proof_format), vc) => {
            let err_msg = format!(
                "Credential/proof format mismatch. Proof format: {}, credential format: {}",
                proof_format,
                match vc {
                    CredentialOrJWT::JWT(_) => "JWT".to_string(),
                    CredentialOrJWT::Credential(_) => "LDP".to_string(),
                }
            );
            return Err((StatusCode::BAD_REQUEST, err_msg).into());
        }
    };
    Ok(Json(res))
}
