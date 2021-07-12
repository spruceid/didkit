/*
To generate test vectors:
    ln -s ../did-test-suite/packages/did-core-test-server/suites/implementations impl
    cargo run --example did-test-suite method key > impl/did-key-spruce.json
    cargo run --example did-test-suite method web > impl/did-web-spruce.json
    cargo run --example did-test-suite resolver key > impl/resolver-spruce-key.json
    cargo run --example did-test-suite resolver web > impl/resolver-spruce-web.json
    cargo run --example did-test-suite dereferencer key > impl/dereferencer-spruce-key.json
    cargo run --example did-test-suite dereferencer web > impl/dereferencer-spruce-web.json
*/

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap as Map, HashMap};
use std::env::Args;

use ssi::did::{Document, DIDURL};
use ssi::did_resolve::{
    dereference, Content, ContentMetadata, DIDResolver, DereferencingInputMetadata,
    DereferencingMetadata, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
    ERROR_INVALID_DID, ERROR_INVALID_DID_URL, ERROR_NOT_FOUND, ERROR_REPRESENTATION_NOT_SUPPORTED,
    TYPE_DID_LD_JSON,
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
#[serde(untagged)]
pub enum ExecutionInput {
    #[serde(rename_all = "camelCase")]
    Resolve {
        did: DID,
        resolution_options: ResolutionInputMetadata,
    },
    #[serde(rename_all = "camelCase")]
    Dereference {
        did_url: DID,
        dereference_options: DereferencingInputMetadata,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ExecutionOutput {
    #[serde(rename_all = "camelCase")]
    Resolve {
        did_document: Option<Document>,
        did_resolution_metadata: ResolutionMetadata,
        did_document_metadata: DocumentMetadata,
    },
    #[serde(rename_all = "camelCase")]
    ResolveRepresentation {
        did_document_stream: String,
        did_resolution_metadata: ResolutionMetadata,
        did_document_metadata: DocumentMetadata,
    },
    #[serde(rename_all = "camelCase")]
    Dereference {
        dereferencing_metadata: DereferencingMetadata,
        content_stream: String,
        content_metadata: ContentMetadata,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResolverExecution {
    pub function: ResolverFunction,
    pub input: ExecutionInput,
    pub output: ExecutionOutput,
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
    assert_eq!(res_meta.content_type, None);
    let mut did_data = Map::new();

    let input_meta = ResolutionInputMetadata {
        accept: Some(TYPE_DID_LD_JSON.to_string()),
        ..Default::default()
    };
    let (res_repr_meta, doc_repr, _doc_repr_meta_opt) =
        resolver.resolve_representation(did, &input_meta).await;
    assert_eq!(res_repr_meta.error, None);
    let representation = String::from_utf8(doc_repr).unwrap();
    let content_type = res_repr_meta.content_type.clone().unwrap();
    assert_eq!(content_type, TYPE_DID_LD_JSON);

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
        did_resolution_metadata: res_repr_meta,
    };
    did_data.insert(content_type, resolution_result);
    let did_vector = DIDVector {
        did_document_data_model: DIDDocumentDataModel { properties },
        did_data,
    };
    did_vector
}

async fn report_method_key() {
    let did_parameters = Map::new();
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
    let did_parameters = Map::new();
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
                ERROR_INVALID_DID_URL => return Self::InvalidDIDURLErrorOutcome,
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
        let input = ExecutionInput::Resolve {
            did: did.to_string(),
            resolution_options: options.to_owned(),
        };
        let error_opt = res_meta.error.clone();
        let doc_meta = doc_meta_opt.unwrap_or_default();
        let deactivated_opt = doc_meta.deactivated.clone();
        let output = ExecutionOutput::Resolve {
            did_document: doc_opt,
            did_resolution_metadata: res_meta,
            did_document_metadata: doc_meta,
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
        let input = ExecutionInput::Resolve {
            did: did.to_string(),
            resolution_options: options.to_owned(),
        };
        let error_opt = res_meta.error.clone();
        let doc_meta = doc_meta_opt.unwrap_or_default();
        let deactivated_opt = doc_meta.deactivated.clone();
        let output = ExecutionOutput::ResolveRepresentation {
            did_document_stream: representation,
            did_resolution_metadata: res_meta,
            did_document_metadata: doc_meta,
        };
        let execution = ResolverExecution {
            function: ResolverFunction::ResolveRepresentation,
            input,
            output,
        };
        self.add_execution(execution, error_opt, deactivated_opt);
    }

    async fn dereference(
        &mut self,
        resolver: &dyn DIDResolver,
        did_url: &str,
        options: &DereferencingInputMetadata,
    ) {
        let (deref_meta, content, content_meta) = dereference(resolver, did_url, options).await;
        let input = ExecutionInput::Dereference {
            did_url: did_url.to_string(),
            dereference_options: options.to_owned(),
        };
        let error_opt = deref_meta.error.clone();
        let deactivated_opt = if let ContentMetadata::DIDDocument(ref did_doc_meta) = content_meta {
            did_doc_meta.deactivated
        } else {
            None
        };
        let content_stream = match content {
            Content::DIDDocument(doc) => serde_json::to_string(&doc).unwrap(),
            Content::URL(url) => String::from(url),
            Content::Object(resource) => serde_json::to_string(&resource).unwrap(),
            Content::Data(vec) => String::from_utf8(vec).unwrap(),
            Content::Null => "".to_string(),
        };
        let output = ExecutionOutput::Dereference {
            dereferencing_metadata: deref_meta,
            content_stream,
            content_metadata: content_meta,
        };
        let execution = ResolverExecution {
            function: ResolverFunction::Dereference,
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

async fn report_dereferencer_key() {
    let mut report = DIDResolverImplementation {
        did_method: "did:key".to_string(),
        implementation: "ssi/didkit".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did_url in vec![
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        "bad:invalid",
    ] {
        report
            .dereference(
                &did_method_key::DIDKey,
                did_url,
                &DereferencingInputMetadata::default(),
            )
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_dereferencer_web() {
    let mut report = DIDResolverImplementation {
        did_method: "did:web".to_string(),
        implementation: "ssi/didkit".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did_url in vec!["did:web:did.actor:nonexistent"] {
        report
            .dereference(
                &did_web::DIDWeb,
                did_url,
                &DereferencingInputMetadata::default(),
            )
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_method(mut args: Args) {
    let method = args.next().expect("expected method argument");
    args.next().ok_or(()).expect_err("unexpected argument");
    match &method[..] {
        "key" => report_method_key().await,
        "web" => report_method_web().await,
        method => panic!("unknown method {}", method),
    }
}

async fn report_resolver(mut args: Args) {
    let method = args.next().expect("expected method argument");
    args.next().ok_or(()).expect_err("unexpected argument");
    match &method[..] {
        "key" => report_resolver_key().await,
        "web" => report_resolver_web().await,
        method => panic!("unknown method {}", method),
    }
}

async fn report_dereferencer(mut args: Args) {
    let method = args.next().expect("expected method argument");
    args.next().ok_or(()).expect_err("unexpected argument");
    match &method[..] {
        "key" => report_dereferencer_key().await,
        "web" => report_dereferencer_web().await,
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
        "dereferencer" => report_dereferencer(args).await,
        section => panic!("unknown section {}", section),
    }
}
