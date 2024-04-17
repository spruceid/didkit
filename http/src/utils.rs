use std::str::FromStr;

use anyhow::anyhow;
use axum::{
    async_trait,
    extract::{rejection::JsonRejection, FromRequest},
    http::Request,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

pub struct CustomErrorJson<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for CustomErrorJson<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let req = Request::from_parts(parts, body);

        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => {
                let message = rejection.to_string();
                let code = if let JsonRejection::JsonDataError(_) = rejection {
                    StatusCode::BAD_REQUEST
                } else {
                    rejection.status()
                };
                Err((code, message))
            }
        }
    }
}

// https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
/// Object summarizing a verification
/// Reference: vc-http-api
pub struct VerificationResult {
    /// The checks performed
    pub checks: Vec<Check>,
    /// Warnings
    pub warnings: Vec<String>,
    /// Errors
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "String")]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Check {
    Proof,
    #[serde(rename = "JWS")]
    JWS,
    Status,
}

impl FromStr for Check {
    type Err = anyhow::Error;
    fn from_str(purpose: &str) -> Result<Self, Self::Err> {
        match purpose {
            "proof" => Ok(Self::Proof),
            "JWS" => Ok(Self::JWS),
            "credentialStatus" => Ok(Self::Status),
            _ => Err(anyhow!("Unsupported check")),
        }
    }
}

impl TryFrom<String> for Check {
    type Error = anyhow::Error;
    fn try_from(purpose: String) -> Result<Self, Self::Error> {
        Self::from_str(&purpose)
    }
}

impl From<Check> for String {
    fn from(check: Check) -> String {
        match check {
            Check::Proof => "proof".to_string(),
            Check::JWS => "JWS".to_string(),
            Check::Status => "credentialStatus".to_string(),
        }
    }
}
