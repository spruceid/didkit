/*
To generate test vectors:
    ln -s ../did-test-suite/packages/did-core-test-server/suites/implementations impl
    cargo run --example did-test-suite method key > impl/did-key-spruce.json
    cargo run --example did-test-suite method web > impl/did-web-spruce.json
    cargo run --example did-test-suite resolver key > impl/resolver-spruce-key.json
    cargo run --example did-test-suite resolver web > impl/resolver-spruce-web.json
*/

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap as Map, HashMap};
use std::env::Args;

use ssi::did::{Document, DIDURL};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ResolutionResult,
    ERROR_INVALID_DID, ERROR_METHOD_NOT_SUPPORTED, ERROR_NOT_FOUND,
    ERROR_REPRESENTATION_NOT_SUPPORTED, ERROR_UNAUTHORIZED, TYPE_DID_LD_JSON, TYPE_LD_JSON,
};

type DID = String;
type ContentType = String;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct RepresentationSpecificEntries {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDDocumentDataModel {
    pub properties: Map<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDDocumentDataModel2 {
    pub representation_specific_entries: RepresentationSpecificEntries,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDData {
    pub did_document_data_model: DIDDocumentDataModel2,
    pub representation: String,
    pub did_document_metadata: DocumentMetadata,
    pub did_resolution_metadata: ResolutionMetadata,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDVector {
    pub did_document_data_model: DIDDocumentDataModel,
    #[serde(flatten)]
    pub did_data: Map<ContentType, DIDData>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDImplementation {
    pub did_method: String,
    pub implementation: String,
    pub implementer: String,
    pub supported_content_types: Vec<ContentType>,
    pub dids: Vec<DID>,
    pub did_parameters: Map<String, DIDURL>,
    #[serde(flatten)]
    pub did_vectors: Map<DID, DIDVector>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum ResolverOutcome {
    DefaultOutcome,
    #[serde(rename = "invalidDidErrorOutcome")]
    InvalidDIDErrorOutcome,
    #[serde(rename = "invalidDidUrlErrorOutcome")]
    InvalidDIDURLErrorOutcome,
    NotFoundErrorOutcome,
    RepresentationNotSupportedErrorOutcome,
    DeactivatedOutcome,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ResolverFunction {
    Resolve,
    ResolveRepresentation,
    Dereference,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResolverInput {
    pub did: DID,
    pub resolution_options: ResolutionInputMetadata,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResolverOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<Document>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_stream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_resolution_metadata: Option<ResolutionMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_metadata: Option<DocumentMetadata>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResolverExecution {
    pub function: ResolverFunction,
    pub input: ResolverInput,
    pub output: ResolverOutput,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDResolverImplementation {
    pub did_method: String,
    pub implementation: String,
    pub implementer: String,
    pub expected_outcomes: HashMap<ResolverOutcome, Vec<usize>>,
    pub executions: Vec<ResolverExecution>,
}

async fn did_method_vector(resolver: &dyn DIDResolver, did: &str) -> DIDVector {
    let (res_meta, doc, doc_meta_opt) = resolver
        .resolve(did, &ResolutionInputMetadata::default())
        .await;
    assert_eq!(res_meta.error, None);
    let doc_meta = doc_meta_opt.unwrap();
    let content_type = res_meta.content_type.clone().unwrap();
    assert_eq!(content_type, TYPE_DID_LD_JSON);
    let mut did_data = Map::new();

    let input_meta = ResolutionInputMetadata {
        accept: Some(content_type.clone()),
        ..Default::default()
    };
    let (res_repr_meta, doc_repr, _doc_repr_meta_opt) =
        resolver.resolve_representation(did, &input_meta).await;
    assert_eq!(res_repr_meta.error, None);
    let representation = String::from_utf8(doc_repr).unwrap();

    let mut doc_value = serde_json::to_value(doc).unwrap();
    let mut representation_specific_entries = RepresentationSpecificEntries::default();
    match &content_type[..] {
        TYPE_DID_LD_JSON => {
            representation_specific_entries.context =
                doc_value.as_object_mut().unwrap().remove("@context");
        }
        _ => unreachable!(),
    }
    let properties: Map<String, Value> = serde_json::from_value(doc_value).unwrap();
    let resolution_result = DIDData {
        did_document_data_model: DIDDocumentDataModel2 {
            representation_specific_entries,
        },
        representation,
        did_document_metadata: doc_meta,
        did_resolution_metadata: res_meta,
    };
    did_data.insert(content_type, resolution_result);
    let did_vector = DIDVector {
        did_document_data_model: DIDDocumentDataModel { properties },
        did_data,
    };
    did_vector
}

async fn report_method_key() {
    let mut did_parameters = Map::new();
    // No parameters supported for did:key
    // did_parameters.insert("".to_string(), DIDURL::from_str("").unrwap());
    let mut did_vectors = Map::new();
    let supported_content_types = vec![TYPE_DID_LD_JSON.to_string()];

    for did in vec![
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", // Ed25519
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme", // Secp256k1
        "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169", // Secp256r1
    ] {
        let did_vector = did_method_vector(&did_method_key::DIDKey, did).await;
        did_vectors.insert(did.to_string(), did_vector);
    }

    let dids = did_vectors.keys().cloned().collect();
    let report = DIDImplementation {
        did_method: "did:key".to_string(),
        implementation: "ssi/didkit".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        supported_content_types,
        dids,
        did_parameters,
        did_vectors,
    };
    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_method_web() {
    let mut did_parameters = Map::new();
    // No parameters supported for did:web
    // did_parameters.insert("".to_string(), DIDURL::from_str("").unrwap());
    let mut did_vectors = Map::new();
    let supported_content_types = vec![TYPE_DID_LD_JSON.to_string()];

    let did = "did:web:demo.spruceid.com:2021:07:08";
    let did_vector = did_method_vector(&did_web::DIDWeb, did).await;
    did_vectors.insert(did.to_string(), did_vector);

    let dids = did_vectors.keys().cloned().collect();
    let report = DIDImplementation {
        did_method: "did:web".to_string(),
        implementation: "ssi/didkit".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        supported_content_types,
        dids,
        did_parameters,
        did_vectors,
    };
    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

impl ResolverOutcome {
    fn from_error_or_deactivated(error: Option<String>, deactivated: Option<bool>) -> Self {
        if let Some(error) = error {
            match &error[..] {
                ERROR_INVALID_DID => return Self::InvalidDIDErrorOutcome,
                ERROR_REPRESENTATION_NOT_SUPPORTED => {
                    return Self::RepresentationNotSupportedErrorOutcome
                }
                ERROR_NOT_FOUND => return Self::NotFoundErrorOutcome,
                _ => panic!("Unknown outcome for error: {}", error),
            }
        }
        if deactivated == Some(true) {
            return Self::DeactivatedOutcome;
        }
        return Self::DefaultOutcome;
    }
}

impl DIDResolverImplementation {
    async fn resolve(
        &mut self,
        resolver: &dyn DIDResolver,
        did: &str,
        options: &ResolutionInputMetadata,
    ) {
        let (res_meta, doc_opt, doc_meta_opt) = resolver.resolve(did, options).await;
        let input = ResolverInput {
            did: did.to_string(),
            resolution_options: options.to_owned(),
        };
        let error_opt = res_meta.error.clone();
        let doc_meta = doc_meta_opt.unwrap_or_default();
        let deactivated_opt = doc_meta.deactivated.clone();
        let output = ResolverOutput {
            did_document: doc_opt,
            did_resolution_metadata: Some(res_meta),
            did_document_metadata: Some(doc_meta),
            ..Default::default()
        };
        let execution = ResolverExecution {
            function: ResolverFunction::Resolve,
            input,
            output,
        };
        self.add_execution(execution, error_opt, deactivated_opt);
    }

    async fn resolve_representation(
        &mut self,
        resolver: &dyn DIDResolver,
        did: &str,
        options: &ResolutionInputMetadata,
    ) {
        let (res_meta, doc_repr, doc_meta_opt) =
            resolver.resolve_representation(did, options).await;
        let representation = String::from_utf8(doc_repr).unwrap();
        let input = ResolverInput {
            did: did.to_string(),
            resolution_options: options.to_owned(),
        };
        let error_opt = res_meta.error.clone();
        let doc_meta = doc_meta_opt.unwrap_or_default();
        let deactivated_opt = doc_meta.deactivated.clone();
        let output = ResolverOutput {
            did_document_stream: Some(representation),
            did_resolution_metadata: Some(res_meta),
            did_document_metadata: Some(doc_meta),
            ..Default::default()
        };
        let execution = ResolverExecution {
            function: ResolverFunction::ResolveRepresentation,
            input,
            output,
        };
        self.add_execution(execution, error_opt, deactivated_opt);
    }

    fn add_execution(
        &mut self,
        execution: ResolverExecution,
        error_opt: Option<String>,
        deactivated_opt: Option<bool>,
    ) {
        let i = self.executions.len();
        self.executions.push(execution);
        let outcome = ResolverOutcome::from_error_or_deactivated(error_opt, deactivated_opt);
        self.expected_outcomes.entry(outcome).or_default().push(i);
    }
}

async fn report_resolver_key() {
    let mut report = DIDResolverImplementation {
        did_method: "did:key".to_string(),
        implementation: "ssi/didkit".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did in vec![
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", // Ed25519
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme", // Secp256k1
        "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169", // Secp256r1
        "did:key;invalid",
    ] {
        report
            .resolve(
                &did_method_key::DIDKey,
                did,
                &ResolutionInputMetadata::default(),
            )
            .await;
    }

    for did in vec!["did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"] {
        report
            .resolve_representation(
                &did_method_key::DIDKey,
                did,
                &ResolutionInputMetadata::default(),
            )
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_resolver_web() {
    let mut report = DIDResolverImplementation {
        did_method: "did:web".to_string(),
        implementation: "ssi/didkit".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did in vec![
        "did:web:identity.foundation",
        "did:web:did.actor:nonexistent",
    ] {
        report
            .resolve(&did_web::DIDWeb, did, &ResolutionInputMetadata::default())
            .await;
    }

    for did in vec!["did:web:identity.foundation"] {
        report
            .resolve_representation(&did_web::DIDWeb, did, &ResolutionInputMetadata::default())
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_method(mut args: std::env::Args) {
    let method = args.next().expect("expected method argument");
    match &method[..] {
        "key" => report_method_key().await,
        "web" => report_method_web().await,
        method => panic!("unknown method {}", method),
    }
}

async fn report_resolver(mut args: std::env::Args) {
    let method = args.next().expect("expected method argument");
    match &method[..] {
        "key" => report_resolver_key().await,
        "web" => report_resolver_web().await,
        method => panic!("unknown method {}", method),
    }
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args();
    args.next();
    let section = args.next().expect("expected section argument");
    match &section[..] {
        "method" => report_method(args).await,
        "resolver" => report_resolver(args).await,
        section => panic!("unknown section {}", section),
    }
}
