use percent_encoding::percent_decode;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use didkit::resolve_key;
use didkit::{
    dereference as dereference_did_url, Content, ContentMetadata, CredentialOrJWT, DIDResolver,
    DereferencingInputMetadata, JWTOrLDPOptions, LinkedDataProofOptions, ProofFormat,
    ResolutionResult, VerifiableCredential, VerifiablePresentation, VerificationResult, JWK,
};
use didkit_cli::opts::ResolverOptions;
use ssi::did_resolve::{
    ERROR_INVALID_DID, ERROR_NOT_FOUND, ERROR_REPRESENTATION_NOT_SUPPORTED, TYPE_DID_LD_JSON,
    TYPE_DID_RESOLUTION,
};

pub mod accept;
pub mod error;
use accept::HttpAccept;
pub use error::Error;

use hyper::body::Buf;
use hyper::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use hyper::{Body, Response};
use hyper::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_service::Service;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum PresentationOrJWT {
    VP(VerifiablePresentation),
    JWT(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct IssueCredentialRequest {
    pub credential: VerifiableCredential,
    pub options: Option<JWTOrLDPOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct VerifyCredentialRequest {
    pub verifiable_credential: CredentialOrJWT,
    pub options: Option<JWTOrLDPOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ProvePresentationRequest {
    pub presentation: VerifiablePresentation,
    pub options: Option<JWTOrLDPOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct VerifyPresentationRequest {
    pub verifiable_presentation: PresentationOrJWT,
    pub options: Option<JWTOrLDPOptions>,
}

pub type IssueCredentialResponse = VerifiableCredential;
pub type VerifyCredentialResponse = VerificationResult;
pub type ProvePresentationResponse = VerifiablePresentation;
pub type VerifyPresentationResponse = VerificationResult;

/// Mapping from public keys to private keys
type KeyMap = HashMap<JWK, JWK>;

pub struct DIDKitHTTPSvc {
    keys: KeyMap,
    resolver_options: ResolverOptions,
}

pub async fn pick_key<'a>(
    keys: &'a KeyMap,
    options: &LinkedDataProofOptions,
    did_resolver: &dyn DIDResolver,
) -> Option<&'a JWK> {
    if keys.len() <= 1 {
        return keys.values().next();
    }
    let vm = match options.verification_method {
        Some(ref verification_method) => verification_method,
        None => return keys.values().next(),
    };
    let public_key = match resolve_key(vm, did_resolver).await {
        Err(_err) => {
            // TODO: return error
            return None;
        }
        Ok(key) => key,
    };
    keys.get(&public_key)
}

impl DIDKitHTTPSvc {
    pub fn new(keys: KeyMap, resolver_options: ResolverOptions) -> Self {
        Self {
            keys,
            resolver_options,
        }
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
        let resolver_options = self.resolver_options.clone();
        Box::pin(async move {
            let body_reader = hyper::body::aggregate(req).await?.reader();
            let issue_req: IssueCredentialRequest = match serde_json::from_reader(body_reader) {
                Ok(reader) => reader,
                Err(err) => {
                    return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                }
            };
            let options = issue_req.options.unwrap_or_default();
            let proof_format = options.proof_format.unwrap_or_default();
            let resolver = resolver_options.to_resolver();
            let key = match pick_key(&keys, &options.ldp_options, &resolver).await {
                Some(key) => key,
                None => return Self::missing_key().await,
            };
            let mut credential = issue_req.credential;
            let body = match proof_format {
                ProofFormat::JWT => {
                    let jwt = match credential
                        .generate_jwt(Some(&key), &options.ldp_options)
                        .await
                    {
                        Ok(reader) => reader,
                        Err(err) => {
                            return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                        }
                    };
                    Body::from(jwt.into_bytes())
                }
                ProofFormat::LDP => {
                    let proof = match credential.generate_proof(key, &options.ldp_options).await {
                        Ok(reader) => reader,
                        Err(err) => {
                            return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                        }
                    };
                    credential.add_proof(proof);
                    Body::from(serde_json::to_vec_pretty(&credential)?)
                }
                _ => {
                    return Self::response(
                        StatusCode::BAD_REQUEST,
                        format!("Unknown proof format: {}", proof_format),
                    )
                    .await;
                }
            };

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
        let resolver_options = self.resolver_options.clone();
        Box::pin(async move {
            let body_reader = hyper::body::aggregate(req).await?.reader();
            let verify_req: VerifyCredentialRequest = match serde_json::from_reader(body_reader) {
                Ok(reader) => reader,
                Err(err) => {
                    return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                }
            };
            let resolver = resolver_options.to_resolver();
            let options = verify_req.options.unwrap_or_default();
            let ldp_options = options.ldp_options;
            let result = match (options.proof_format, verify_req.verifiable_credential) {
                (Some(ProofFormat::LDP), CredentialOrJWT::Credential(vc))
                | (None, CredentialOrJWT::Credential(vc)) => {
                    vc.verify(Some(ldp_options), &resolver).await
                }
                (Some(ProofFormat::JWT), CredentialOrJWT::JWT(vc_jwt))
                | (None, CredentialOrJWT::JWT(vc_jwt)) => {
                    VerifiableCredential::verify_jwt(&vc_jwt, Some(ldp_options), &resolver).await
                }
                (Some(proof_format), vc) => {
                    let err_msg = format!(
                        "Credential/proof format mismatch. Proof format: {}, credential: {}",
                        proof_format,
                        serde_json::to_string(&vc)?
                    );
                    return Self::response(StatusCode::BAD_REQUEST, err_msg).await;
                }
            };
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
        let resolver_options = self.resolver_options.clone();
        Box::pin(async move {
            let body_reader = hyper::body::aggregate(req).await?.reader();
            let issue_req: ProvePresentationRequest = match serde_json::from_reader(body_reader) {
                Ok(reader) => reader,
                Err(err) => {
                    return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                }
            };
            let options = issue_req
                .options
                .unwrap_or_else(JWTOrLDPOptions::default_for_vp);
            let mut presentation = issue_req.presentation;
            let proof_format = options.proof_format.unwrap_or_default();
            let ldp_options = options.ldp_options;
            let resolver = resolver_options.to_resolver();
            let key = match pick_key(&keys, &ldp_options, &resolver).await {
                Some(key) => key,
                None => return Self::missing_key().await,
            };
            let body = match proof_format {
                ProofFormat::JWT => {
                    let jwt = match presentation.generate_jwt(Some(&key), &ldp_options).await {
                        Ok(reader) => reader,
                        Err(err) => {
                            return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                        }
                    };
                    Body::from(jwt.into_bytes())
                }
                ProofFormat::LDP => {
                    let proof = match presentation.generate_proof(key, &ldp_options).await {
                        Ok(reader) => reader,
                        Err(err) => {
                            return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                        }
                    };
                    presentation.add_proof(proof);
                    Body::from(serde_json::to_vec_pretty(&presentation)?)
                }
                _ => {
                    return Self::response(
                        StatusCode::BAD_REQUEST,
                        format!("Unknown proof format: {}", proof_format),
                    )
                    .await;
                }
            };
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
        let resolver_options = self.resolver_options.clone();
        Box::pin(async move {
            let body_reader = hyper::body::aggregate(req).await?.reader();
            let verify_req: VerifyPresentationRequest = match serde_json::from_reader(body_reader) {
                Ok(reader) => reader,
                Err(err) => {
                    return Self::response(StatusCode::BAD_REQUEST, err.to_string()).await;
                }
            };
            let resolver = resolver_options.to_resolver();
            let options = verify_req
                .options
                .unwrap_or_else(JWTOrLDPOptions::default_for_vp);
            let ldp_options = options.ldp_options;
            let result = match (options.proof_format, verify_req.verifiable_presentation) {
                (Some(ProofFormat::LDP), PresentationOrJWT::VP(vp))
                | (None, PresentationOrJWT::VP(vp)) => {
                    vp.verify(Some(ldp_options), &resolver).await
                }
                (Some(ProofFormat::JWT), PresentationOrJWT::JWT(vp_jwt))
                | (None, PresentationOrJWT::JWT(vp_jwt)) => {
                    VerifiablePresentation::verify_jwt(&vp_jwt, Some(ldp_options), &resolver).await
                }
                (Some(proof_format), vp) => {
                    let err_msg = format!(
                        "Presentation/proof format mismatch. Proof format: {}, presentation: {}",
                        proof_format,
                        serde_json::to_string(&vp)?
                    );
                    return Self::response(StatusCode::BAD_REQUEST, err_msg).await;
                }
            };
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

    /// Resolve a DID or dereference a DID URL.
    ///
    /// <https://w3c-ccg.github.io/did-resolution/#bindings-https>
    pub fn resolve_dereference(
        &self,
        req: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
        if req.method() != Method::GET {
            return self.method_not_allowed();
        }
        let uri = req.uri();
        let mut deref_input_meta: DereferencingInputMetadata =
            match serde_urlencoded::from_str(uri.query().unwrap_or("")) {
                Ok(metadata) => metadata,
                Err(err) => {
                    return Self::response(
                        StatusCode::BAD_REQUEST,
                        format!("Unable to parse resolution input metadata: {}", err),
                    );
                }
            };
        let http_accept = match req.headers().get(ACCEPT) {
            Some(header) => match header.to_str() {
                Ok(accept_str) => Some(accept_str.to_string()),
                Err(err) => {
                    return Self::response(
                        StatusCode::BAD_REQUEST,
                        format!("Unable to parse Accept header: {}", err),
                    );
                }
            },
            None => None,
        };
        if deref_input_meta.accept.is_none() && http_accept.is_some() {
            deref_input_meta.accept = http_accept;
        };
        let resolver_options = self.resolver_options.clone();
        Box::pin(async move {
            let uri = req.uri();
            let path: String = uri.path().chars().skip(13).collect();
            let did_url = match percent_decode(path.as_bytes()).decode_utf8() {
                Ok(did_url) => did_url,
                Err(err) => {
                    return Self::response(
                        StatusCode::BAD_REQUEST,
                        format!("Unable to parse DID URL: {}", err),
                    )
                    .await;
                }
            };
            let resolver = resolver_options.to_resolver();
            // skip root "/identifiers/" to get DID
            let (deref_meta, content, content_meta) =
                dereference_did_url(&resolver, &did_url, &deref_input_meta).await;
            let (mut parts, mut body) = Response::<Body>::default().into_parts();
            if let Some(ref error) = deref_meta.error {
                // 1.6, 1.7, 1.8
                parts.status = match &error[..] {
                    ERROR_NOT_FOUND => StatusCode::NOT_FOUND,
                    ERROR_INVALID_DID => StatusCode::BAD_REQUEST,
                    ERROR_REPRESENTATION_NOT_SUPPORTED => StatusCode::NOT_ACCEPTABLE,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                body = Body::from(error.as_bytes().to_vec());
            }
            if let ContentMetadata::DIDDocument(ref did_doc_meta) = content_meta {
                if did_doc_meta.deactivated == Some(true) {
                    parts.status = StatusCode::GONE;
                }
            }
            // 1.10
            match content {
                Content::DIDDocument(did_doc) => {
                    // TODO: Check if type is of a conformant representation?
                    if deref_input_meta.accept != Some(TYPE_DID_RESOLUTION.to_string()) {
                        // 1.10.1
                        let content_type = deref_meta
                            .content_type
                            .unwrap_or_else(|| TYPE_DID_LD_JSON.to_string());
                        let content_type_header = match content_type.parse() {
                            Err(err) => {
                                return Self::response(
                                    StatusCode::BAD_REQUEST,
                                    format!("Unable to parse Content-Type: {}", err),
                                )
                                .await;
                            }
                            Ok(content_type) => content_type,
                        };
                        parts.headers.insert(CONTENT_TYPE, content_type_header);
                        // 1.10.1.3
                        let representation = match did_doc.to_representation(&content_type) {
                            Err(err) => {
                                return Self::response(
                                    StatusCode::NOT_ACCEPTABLE,
                                    format!("Unable to represent DID document: {}", err),
                                )
                                .await;
                            }
                            Ok(content_type) => content_type,
                        };
                        body = Body::from(representation);
                    } else {
                        // 1.10.2
                        // 1.10.2.1
                        let did_doc_meta_opt = match content_meta {
                            ContentMetadata::DIDDocument(meta) => Some(meta),
                            ContentMetadata::Other(map) if map.is_empty() => None,
                            _ => {
                                return Self::response(
                                    StatusCode::NOT_ACCEPTABLE,
                                    format!(
                                    "Expected content-metadata to be a DID Document metadata structure, but found: {:?}", content_meta
                                ),
                                )
                                .await;
                            }
                        };
                        let result = ResolutionResult {
                            did_document: Some(did_doc),
                            did_resolution_metadata: Some(deref_meta.clone().into()),
                            did_document_metadata: did_doc_meta_opt,
                            ..Default::default()
                        };
                        // 1.10.2.3
                        let content_type = match TYPE_DID_RESOLUTION.parse() {
                            Ok(content_type) => content_type,
                            Err(err) => {
                                return Self::response(
                                    StatusCode::BAD_REQUEST,
                                    format!("Unable to parse Content-Type: {}", err),
                                )
                                .await;
                            }
                        };
                        parts.headers.insert(CONTENT_TYPE, content_type);

                        // 1.10.2.4
                        let result_data = match serde_json::to_vec(&result) {
                            Ok(data) => data,
                            Err(err) => {
                                return Self::response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!("Unable to serialize resolution result: {}", err),
                                )
                                .await;
                            }
                        };
                        body = Body::from(result_data);
                    }
                }
                Content::URL(url) => {
                    // 1.11
                    parts.status = StatusCode::SEE_OTHER;
                    let location = match url.parse() {
                        Ok(location) => location,
                        Err(err) => {
                            return Self::response(
                                StatusCode::BAD_REQUEST,
                                format!("Unable to parse service endpoint URL: {}", err),
                            )
                            .await;
                        }
                    };
                    parts.headers.insert(LOCATION, location);
                }
                Content::Object(object) => {
                    let object_data = match serde_json::to_vec(&object) {
                        Ok(data) => data,
                        Err(err) => {
                            return Self::response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("Unable to serialize dereferenced object: {}", err),
                            )
                            .await;
                        }
                    };
                    body = Body::from(object_data);
                }
                Content::Data(data) => {
                    body = Body::from(data);
                }
                Content::Null => {}
            };
            let response = Response::from_parts(parts, body);
            Ok(response)
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
        let path = req.uri().path();
        match path {
            // vc-http-api 0.0.1
            "/issue/credentials" => return self.issue_credentials(req),
            "/verify/credentials" => return self.verify_credentials(req),
            "/prove/presentations" => return self.prove_presentations(req),
            "/verify/presentations" => return self.verify_presentations(req),
            // vc-http-api 0.0.2-unstable
            "/credentials/issue" => return self.issue_credentials(req),
            "/credentials/verify" => return self.verify_credentials(req),
            "/credentials/prove" => return self.prove_presentations(req),
            "/presentations/verify" => return self.verify_presentations(req),
            _ => {}
        };
        if path.starts_with("/identifiers/") {
            // DID Resolution HTTP(S) binding
            return self.resolve_dereference(req);
        }
        self.not_found()
    }
}

pub struct DIDKitHTTPMakeSvc {
    keys: KeyMap,
    resolver_options: ResolverOptions,
}

impl DIDKitHTTPMakeSvc {
    pub fn new(keys: Vec<JWK>, resolver_options: ResolverOptions) -> Self {
        Self {
            keys: keys.into_iter().fold(KeyMap::new(), |mut map, key| {
                map.insert(key.to_public(), key);
                map
            }),
            resolver_options,
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
        let resolver_options = self.resolver_options.clone();
        let fut = async move { Ok(DIDKitHTTPSvc::new(keys, resolver_options)) };
        Box::pin(fut)
    }
}
