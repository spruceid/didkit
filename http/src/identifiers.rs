use anyhow::Context;
use axum::{
    body::Bytes,
    extract::{Path, Query},
    http::{
        header::{CONTENT_TYPE, LOCATION},
        HeaderMap, StatusCode,
    },
};
use didkit::{
    dereference,
    ssi::did_resolve::{
        ERROR_INVALID_DID, ERROR_INVALID_DID_URL, ERROR_METHOD_NOT_SUPPORTED, ERROR_NOT_FOUND,
        ERROR_REPRESENTATION_NOT_SUPPORTED, TYPE_DID_LD_JSON, TYPE_DID_RESOLUTION,
    },
    Content, ContentMetadata, DereferencingInputMetadata, ResolutionResult, DID_METHODS,
};
use percent_encoding::percent_decode;

use crate::error::Error;

pub async fn resolve(
    Path(path): Path<String>,
    Query(metadata): Query<DereferencingInputMetadata>,
) -> Result<(StatusCode, HeaderMap, Bytes), Error> {
    let did_url = percent_decode(path.as_bytes())
        .decode_utf8()
        .context("Could not percent decode path")
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:?}")))?;
    let resolver = DID_METHODS.to_resolver();
    let (deref_meta, content, content_meta) = dereference(resolver, &did_url, &metadata).await;
    if let Some(ref error) = deref_meta.error {
        // 1.6, 1.7, 1.8
        let status = match &error[..] {
            ERROR_NOT_FOUND => StatusCode::NOT_FOUND,
            ERROR_INVALID_DID | ERROR_INVALID_DID_URL => StatusCode::BAD_REQUEST,
            ERROR_REPRESENTATION_NOT_SUPPORTED => StatusCode::NOT_ACCEPTABLE,
            ERROR_METHOD_NOT_SUPPORTED => StatusCode::NOT_IMPLEMENTED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return Err((status, format!("Dereferencing failed: {error}")))?;
    }
    if let ContentMetadata::DIDDocument(ref did_doc_meta) = content_meta {
        if did_doc_meta.deactivated == Some(true) {
            return Err((StatusCode::GONE, "".to_string()))?;
        }
    }

    let mut headers = HeaderMap::new();

    let body = match content {
        Content::DIDDocument(did_doc) => {
            if metadata.accept != Some(TYPE_DID_RESOLUTION.to_string()) {
                // 1.10.1
                let content_type = deref_meta
                    .content_type
                    .unwrap_or_else(|| TYPE_DID_LD_JSON.to_string());
                let content_type_header = content_type.parse().map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Unable to parse Content-Type: {e}"),
                    )
                })?;
                headers.insert(CONTENT_TYPE, content_type_header);
                // 1.10.1.3
                match did_doc.to_representation(&content_type) {
                    Err(err) => {
                        return Err((
                            StatusCode::NOT_ACCEPTABLE,
                            format!("Unable to represent DID document: {}", err),
                        ))?;
                    }
                    Ok(content_type) => content_type,
                }
            } else {
                // 1.10.2
                // 1.10.2.1
                let did_doc_meta_opt = match content_meta {
                    ContentMetadata::DIDDocument(meta) => Some(meta),
                    ContentMetadata::Other(map) if map.is_empty() => None,
                    _ => {
                        return Err((
                        StatusCode::NOT_ACCEPTABLE,
                        format!(
                        "Expected content-metadata to be a DID Document metadata structure, but found: {:?}", content_meta
                    )
                    ))?
                    }
                };
                let result = ResolutionResult {
                    did_document: Some(did_doc),
                    did_resolution_metadata: Some(deref_meta.into()),
                    did_document_metadata: did_doc_meta_opt,
                    ..Default::default()
                };
                // 1.10.2.3
                let content_type = match TYPE_DID_RESOLUTION.parse() {
                    Ok(content_type) => content_type,
                    Err(err) => {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            format!("Unable to parse Content-Type: {}", err),
                        ))?;
                    }
                };
                headers.insert(CONTENT_TYPE, content_type);

                // 1.10.2.4
                match serde_json::to_vec(&result) {
                    Ok(data) => data,
                    Err(err) => {
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unable to serialize resolution result: {}", err),
                        ))?;
                    }
                }
            }
        }
        Content::URL(url) => {
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
        Content::Object(object) => match serde_json::to_vec(&object) {
            Ok(data) => data,
            Err(err) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Unable to serialize dereferenced object: {}", err),
                ))?;
            }
        },
        Content::Data(data) => data,
        Content::Null => {
            vec![]
        }
    };

    Ok((StatusCode::OK, headers, body.into()))
}
