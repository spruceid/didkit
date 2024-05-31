//! DID Resolution server-side HTTP Binding implementation.
//!
//! See: <https://w3c-ccg.github.io/did-resolution/#bindings-https>
use crate::{error::Error, utils::Accept};
use anyhow::Context;
use axum::{
    body::Bytes,
    extract::{Path, Query},
    http::{
        header::{CONTENT_TYPE, LOCATION},
        HeaderMap, HeaderValue, StatusCode,
    },
};
use axum_extra::TypedHeader;
use didkit::ssi::dids::{
    document::representation, http::ResolutionResult, resolution, AnyDidMethod, DIDResolver,
    DIDURLBuf, InvalidDIDURL, DID,
};
use percent_encoding::percent_decode;

pub const DID_RESOLUTION_MEDIA_TYPE: &str =
    "application/ld+json;profile=\"https://w3id.org/did-resolution\"";

enum ContentType {
    JsonLdDidResolution,
    Other(representation::MediaType),
}

impl ContentType {
    fn representation(&self) -> representation::MediaType {
        match self {
            Self::JsonLdDidResolution => representation::MediaType::JsonLd,
            Self::Other(t) => *t,
        }
    }

    pub fn header(&self) -> HeaderValue {
        HeaderValue::from_str(match self {
            Self::JsonLdDidResolution => DID_RESOLUTION_MEDIA_TYPE,
            Self::Other(other) => other.name(),
        })
        .unwrap()
    }
}

pub async fn resolve(
    Path(path): Path<String>,
    Query(mut options): Query<resolution::Options>,
    accept: Option<TypedHeader<Accept>>,
) -> Result<(StatusCode, HeaderMap, Bytes), Error> {
    let did_url: DIDURLBuf = percent_decode(path.as_bytes())
        .decode_utf8()
        .context("Could not percent decode path")
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:?}")))?
        .parse()
        .map_err(|e: InvalidDIDURL<String>| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let content_type = match accept {
        Some(TypedHeader(accept)) => {
            if accept == DID_RESOLUTION_MEDIA_TYPE {
                ContentType::JsonLdDidResolution
            } else {
                match accept.as_str().parse() {
                    Ok(other) => ContentType::Other(other),
                    Err(unknown) => {
                        return Err((StatusCode::NOT_ACCEPTABLE, unknown.to_string()).into())
                    }
                }
            }
        }
        None => ContentType::Other(representation::MediaType::JsonLd),
    };

    let resolver = AnyDidMethod::default();

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, content_type.header());

    let body = match DID::new(&did_url).ok() {
        Some(did) => {
            options.accept = Some(content_type.representation());
            let result = resolver.resolve_representation(did, options).await;

            match result {
                Ok(output) => {
                    if output.document_metadata.deactivated.unwrap_or(false) {
                        return Err((StatusCode::GONE, "".to_string()))?;
                    }

                    match content_type {
                        ContentType::JsonLdDidResolution => {
                            serde_json::to_vec(&ResolutionResult::Success {
                                content: String::from_utf8(output.document).map_err(|_| {
                                    (
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        "Non UTF-8 representation".to_string(),
                                    )
                                })?,
                                metadata: output.metadata,
                                document_metadata: output.document_metadata,
                            })
                            .unwrap()
                        }
                        ContentType::Other(_) => output.document,
                    }
                }
                Err(e) => match content_type {
                    ContentType::JsonLdDidResolution => {
                        serde_json::to_vec(&ResolutionResult::Failure { error: e.into() }).unwrap()
                    }
                    _ => return Err(e.into()),
                },
            }
        }
        None => {
            let result = resolver.dereference(&did_url).await;

            match result {
                Ok(output) => {
                    if output.content_metadata.deactivated.unwrap_or(false) {
                        return Err((StatusCode::GONE, "".to_string()))?;
                    }

                    let bytes = match output.content {
                        resolution::Content::Resource(resource) => {
                            serde_json::to_vec(&resource).unwrap()
                        }
                        resolution::Content::Url(url) => {
                            // 1.11
                            let location = match url.parse() {
                                Ok(location) => location,
                                Err(err) => {
                                    return Err((
                                        StatusCode::BAD_REQUEST,
                                        format!("Unable to parse service endpoint URL: {}", err),
                                    ))?;
                                }
                            };
                            headers.insert(LOCATION, location);
                            return Ok((StatusCode::SEE_OTHER, headers, vec![].into()));
                        }
                        resolution::Content::Null => Vec::new(),
                    };

                    match content_type {
                        ContentType::JsonLdDidResolution => {
                            serde_json::to_vec(&ResolutionResult::Success {
                                content: String::from_utf8(bytes).map_err(|_| {
                                    (
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        "Non UTF-8 representation".to_string(),
                                    )
                                })?,
                                metadata: output.metadata,
                                document_metadata: output.content_metadata,
                            })
                            .unwrap()
                        }
                        _ => bytes,
                    }
                }
                Err(e) => match content_type {
                    ContentType::JsonLdDidResolution => {
                        serde_json::to_vec(&ResolutionResult::Failure { error: e.into() }).unwrap()
                    }
                    _ => return Err(e.into()),
                },
            }
        }
    };

    Ok((StatusCode::OK, headers, body.into()))
}
