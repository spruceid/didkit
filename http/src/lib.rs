use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use didkit::{
    LinkedDataProofOptions, ProofPurpose, VerifiableCredential, VerifiablePresentation,
    VerificationResult, JWK,
};

pub mod accept;
pub mod error;
use accept::HttpAccept;
pub use error::Error;

use bytes::buf::BufExt;
use hyper::header::{ACCEPT, CONTENT_TYPE};
use hyper::{Body, Response};
use hyper::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_service::Service;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct IssueCredentialRequest {
    pub credential: VerifiableCredential,
    pub options: Option<LinkedDataProofOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct VerifyCredentialRequest {
    pub verifiable_credential: VerifiableCredential,
    pub options: Option<LinkedDataProofOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ProvePresentationRequest {
    pub presentation: VerifiablePresentation,
    pub options: Option<LinkedDataProofOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct VerifyPresentationRequest {
    pub verifiable_presentation: VerifiablePresentation,
    pub options: Option<LinkedDataProofOptions>,
}

pub type IssueCredentialResponse = VerifiableCredential;
pub type VerifyCredentialResponse = VerificationResult;
pub type ProvePresentationResponse = VerifiablePresentation;
pub type VerifyPresentationResponse = VerificationResult;

type KeyMap = HashMap<String, JWK>;

pub struct DIDKitHTTPSvc {
    keys: KeyMap,
}

pub fn pick_key<'a>(keys: &'a KeyMap, options: &LinkedDataProofOptions) -> Option<&'a JWK> {
    if keys.len() <= 1 {
        keys.values().next()
    } else {
        match options.verification_method {
            Some(ref verification_method) => keys.get(verification_method),
            None => keys.values().next(),
        }
    }
}

impl DIDKitHTTPSvc {
    pub fn new(keys: KeyMap) -> Self {
        Self { keys }
    }

    pub fn response(
        status_code: StatusCode,
        text: String,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
        Box::pin(async move {
            let value = json!(text);
            let body = Body::from(serde_json::to_vec_pretty(&value)?);
            Response::builder()
                .status(status_code)
                .header(CONTENT_TYPE, "application/json")
                .body(body)
                .map_err(|err| err.into())
        })
    }

    pub fn ensure_json(
        &self,
        req: &Request<Body>,
    ) -> Option<Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>> {
        if let Some(content_type) = req.headers().get(CONTENT_TYPE) {
            if content_type != "application/json" {
                return Some(Self::response(
                    StatusCode::BAD_REQUEST,
                    "Expected application/json".to_string(),
                ));
            }
        }
        None
    }

    pub fn ensure_accept_json(
        &self,
        req: &Request<Body>,
    ) -> Option<Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>> {
        let accept = match req.headers().get(ACCEPT) {
            Some(accept) => accept,
            None => return None,
        };
        let accept = match match accept.to_str() {
            Ok(accept) => HttpAccept::from_str(accept),
            Err(err) => Err(err.into()),
        } {
            Ok(accept) => accept,
            Err(err) => {
                return Some(Self::response(
                    StatusCode::BAD_REQUEST,
                    "Unable to parse Accept header: ".to_string() + &err.to_string(),
                ))
            }
        };
        if accept.can_accept("application/json") {
            return None;
        }
        return Some(Self::response(
            StatusCode::NOT_ACCEPTABLE,
            "Response can only be application/json".to_string(),
        ));
    }

    pub fn method_not_allowed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
        Self::response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed".to_string(),
        )
    }

    pub fn not_found(&self) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
        Self::response(StatusCode::NOT_FOUND, "Not found".to_owned())
    }

    pub fn missing_key() -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
        Self::response(StatusCode::INTERNAL_SERVER_ERROR, "Missing key".to_string())
    }

    pub fn issue_credentials(
        &self,
        req: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
        if req.method() != Method::POST {
            return self.method_not_allowed();
        }
        if let Some(resp) = self.ensure_json(&req) {
            return resp;
        };
        if let Some(resp) = self.ensure_accept_json(&req) {
            return resp;
        };
        let keys = self.keys.clone();
        Box::pin(async move {
            let body_reader = hyper::body::aggregate(req).await?.reader();
            let issue_req: IssueCredentialRequest = match serde_json::from_reader(body_reader) {
                Ok(reader) => reader,
                Err(err) => {
                    return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                }
            };
            let options = issue_req.options.unwrap_or_default();
            let key = match pick_key(&keys, &options) {
                Some(key) => key,
                None => return Self::missing_key().await,
            };
            let mut credential = issue_req.credential;
            let proof = match credential.generate_proof(key, &options).await {
                Ok(reader) => reader,
                Err(err) => {
                    return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                }
            };
            credential.add_proof(proof);
            let body = Body::from(serde_json::to_vec_pretty(&credential)?);
            Response::builder()
                .status(StatusCode::CREATED)
                .header(CONTENT_TYPE, "application/json")
                .body(body)
                .map_err(|err| err.into())
        })
    }

    pub fn verify_credentials(
        &self,
        req: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
        if req.method() != Method::POST {
            return self.method_not_allowed();
        }
        if let Some(resp) = self.ensure_json(&req) {
            return resp;
        };
        if let Some(resp) = self.ensure_accept_json(&req) {
            return resp;
        };
        Box::pin(async move {
            let body_reader = hyper::body::aggregate(req).await?.reader();
            let verify_req: VerifyCredentialRequest = match serde_json::from_reader(body_reader) {
                Ok(reader) => reader,
                Err(err) => {
                    return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                }
            };
            let credential = verify_req.verifiable_credential;
            let result = credential.verify(verify_req.options).await;
            let body = Body::from(serde_json::to_vec_pretty(&result)?);
            Response::builder()
                .status(match result.errors.is_empty() {
                    true => StatusCode::OK,
                    false => StatusCode::BAD_REQUEST,
                })
                .header(CONTENT_TYPE, "application/json")
                .body(body)
                .map_err(|err| err.into())
        })
    }

    pub fn prove_presentations(
        &self,
        req: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
        if req.method() != Method::POST {
            return self.method_not_allowed();
        }
        if let Some(resp) = self.ensure_json(&req) {
            return resp;
        };
        if let Some(resp) = self.ensure_accept_json(&req) {
            return resp;
        };
        let keys = self.keys.clone();
        Box::pin(async move {
            let body_reader = hyper::body::aggregate(req).await?.reader();
            let issue_req: ProvePresentationRequest = match serde_json::from_reader(body_reader) {
                Ok(reader) => reader,
                Err(err) => {
                    return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                }
            };
            let options = issue_req.options.unwrap_or_else(|| {
                let mut options = LinkedDataProofOptions::default();
                options.proof_purpose = Some(ProofPurpose::Authentication);
                options
            });
            let mut presentation = issue_req.presentation;
            let options = LinkedDataProofOptions::from(options);
            let key = match pick_key(&keys, &options) {
                Some(key) => key,
                None => return Self::missing_key().await,
            };
            let proof = match presentation.generate_proof(key, &options).await {
                Ok(reader) => reader,
                Err(err) => {
                    return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                }
            };
            presentation.add_proof(proof);
            let body = Body::from(serde_json::to_vec_pretty(&presentation)?);
            Response::builder()
                .status(StatusCode::CREATED)
                .header(CONTENT_TYPE, "application/json")
                .body(body)
                .map_err(|err| err.into())
        })
    }

    pub fn verify_presentations(
        &self,
        req: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
        if req.method() != Method::POST {
            return self.method_not_allowed();
        }
        if let Some(resp) = self.ensure_json(&req) {
            return resp;
        };
        if let Some(resp) = self.ensure_accept_json(&req) {
            return resp;
        };
        Box::pin(async move {
            let body_reader = hyper::body::aggregate(req).await?.reader();
            let verify_req: VerifyPresentationRequest = match serde_json::from_reader(body_reader) {
                Ok(reader) => reader,
                Err(err) => {
                    return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                }
            };
            let presentation = verify_req.verifiable_presentation;
            let result = presentation.verify(verify_req.options).await;
            let body = Body::from(serde_json::to_vec_pretty(&result)?);
            Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .status(match result.errors.is_empty() {
                    true => StatusCode::OK,
                    false => StatusCode::BAD_REQUEST,
                })
                .body(body)
                .map_err(|err| err.into())
        })
    }
}

impl Service<Request<Body>> for DIDKitHTTPSvc {
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let _accept = req.headers().get(ACCEPT);
        match req.uri().path() {
            "/issue/credentials" => self.issue_credentials(req),
            "/verify/credentials" => self.verify_credentials(req),
            "/prove/presentations" => self.prove_presentations(req),
            "/verify/presentations" => self.verify_presentations(req),
            _ => self.not_found(),
        }
    }
}

pub struct DIDKitHTTPMakeSvc {
    keys: KeyMap,
}

impl DIDKitHTTPMakeSvc {
    pub fn new(keys: Vec<JWK>) -> Self {
        Self {
            keys: keys.into_iter().fold(KeyMap::new(), |mut map, key| {
                map.insert(key.to_verification_method().unwrap(), key);
                map
            }),
        }
    }
}

impl<T> Service<T> for DIDKitHTTPMakeSvc {
    type Response = DIDKitHTTPSvc;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: T) -> Self::Future {
        let keys = self.keys.clone();
        let fut = async move { Ok(DIDKitHTTPSvc::new(keys)) };
        Box::pin(fut)
    }
}
