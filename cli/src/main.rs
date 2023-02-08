use std::{
    convert::TryFrom,
    fs::File,
    io::{stdin, stdout, BufReader, BufWriter, Read, Write},
    ops::Deref,
    path::PathBuf,
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Error as AError, Result as AResult};
use chrono::prelude::*;
use clap::{ArgGroup, Args, Parser, Subcommand};
use credential::{CredentialIssueArgs, CredentialVerifyArgs};
use didkit::ssi::{
    jsonld::{self, parse_ld_context, StaticLoader},
    ldp::ProofSuiteType,
    rdf,
};
use didkit::{
    dereference, generate_proof,
    ssi::{
        self,
        did::{DIDMethodTransaction, Service, ServiceEndpoint},
        one_or_many::OneOrMany,
    },
    DIDCreate, DIDDeactivate, DIDDocumentOperation, DIDMethod, DIDRecover, DIDResolver, DIDUpdate,
    DereferencingInputMetadata, Error, LinkedDataProofOptions, Metadata, ProofFormat,
    ResolutionInputMetadata, ResolutionResult, VerifiablePresentation, VerificationRelationship,
    DIDURL, DID_METHODS, JWK, URI,
};
use iref::IriBuf;
use json_ld::JsonLdProcessor;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

mod opts;
use opts::ResolverOptions;
mod credential;
mod did;
mod key;
mod presentation;

#[derive(Parser)]
struct DIDKit {
    #[command(subcommand)]
    command: DIDKitCmd,
}

#[derive(Subcommand)]
pub enum DIDKitCmd {
    /// Generate and output a Ed25519 keypair in JWK format
    #[clap(hide = true)]
    GenerateEd25519Key,
    /// Subcommand for keypair operations
    #[clap(subcommand)]
    Key(key::KeyCmd),
    /// Output a did:key DID for a JWK. Deprecated in favor of key-to-did.
    #[clap(hide = true)]
    KeyToDIDKey(KeyArg),
    /// Deprecated in favor of `didkit key to did`
    #[clap(hide = true)]
    KeyToDID(key::KeyToDIDArgs),
    /// Deprecated in favor of `didkit key to verification-method`
    #[clap(hide = true)]
    KeyToVerificationMethod(key::KeyToVMArgs),
    #[clap(hide = true)]
    SshPkToJwk(key::KeyFromSSHArgs),

    // DID Functionality
    /// Create new DID Document.
    // See also: https://identity.foundation/did-registration/#create
    //           (method), jobId, options, secret, didDocument
    DIDCreate {
        /// DID method name
        method: String,

        /// JWK file for default verification method
        #[clap(short, long)]
        verification_key: Option<PathBuf>,

        /// JWK file for DID Update operations
        #[clap(short, long)]
        update_key: Option<PathBuf>,

        /// JWK file for DID Recovery and/or Deactivate operations
        #[clap(short, long)]
        recovery_key: Option<PathBuf>,

        #[clap(short = 'o', name = "name=value")]
        /// Options for DID create operation
        ///
        /// More info: https://identity.foundation/did-registration/#options
        options: Vec<MetadataProperty>,
    },

    /// Get DID from DID method transaction
    ///
    /// Reads from standard input. Outputs DID on success.
    DIDFromTx,

    /// Submit a DID method transaction
    ///
    /// Reads from standard input.
    DIDSubmitTx,

    /// Update a DID.
    DIDUpdate {
        /// New JWK file for next DID Update operation
        #[clap(short = 'u', long)]
        new_update_key: Option<PathBuf>,

        /// JWK file for performing this DID update operation.
        #[clap(short = 'U', long)]
        update_key: Option<PathBuf>,

        #[clap(short = 'o', name = "name=value")]
        /// Options for DID Update operation
        ///
        /// More info: https://identity.foundation/did-registration/#options
        options: Vec<MetadataProperty>,

        #[clap(subcommand)]
        cmd: DIDUpdateCmd,
    },

    /// Recover a DID.
    DIDRecover {
        /// DID to recover
        did: String,

        /// New JWK file for default verification method
        #[clap(short = 'v', long)]
        new_verification_key: Option<PathBuf>,

        /// New JWK file for DID Update operations
        #[clap(short = 'u', long)]
        new_update_key: Option<PathBuf>,

        /// New JWK file for DID Recovery and/or Deactivate operations
        #[clap(short = 'r', long)]
        new_recovery_key: Option<PathBuf>,

        /// JWK file for performing this DID recover operation.
        #[clap(short = 'R', long)]
        recovery_key: Option<PathBuf>,

        #[clap(short = 'o', name = "name=value")]
        /// Options for DID Recover operation
        ///
        /// More info: https://identity.foundation/did-registration/#options
        options: Vec<MetadataProperty>,
    },

    /// Resolve a DID to a DID Document.
    DIDResolve {
        did: String,
        #[clap(short = 'm', long)]
        /// Return resolution result with metadata
        with_metadata: bool,
        #[clap(short = 'i', name = "name=value")]
        /// DID resolution input metadata
        input_metadata: Vec<MetadataProperty>,
        #[clap(flatten)]
        resolver_options: ResolverOptions,
    },
    /// Dereference a DID URL to a resource.
    DIDDereference {
        did_url: String,
        #[clap(short = 'm', long)]
        /// Return resolution result with metadata
        with_metadata: bool,
        #[clap(short = 'i', name = "name=value")]
        /// DID dereferencing input metadata
        input_metadata: Vec<MetadataProperty>,
        #[clap(flatten)]
        resolver_options: ResolverOptions,
    },
    /// Authenticate with a DID.
    DIDAuth {
        #[clap(flatten)]
        key: KeyArg,
        #[clap(short = 'H', long)]
        holder: String,
        #[clap(flatten)]
        proof_options: ProofOptions,
        #[clap(flatten)]
        resolver_options: ResolverOptions,
    },

    /// Deactivate a DID.
    DIDDeactivate {
        did: String,

        /// Filename of JWK to perform the DID Deactivate operation
        #[clap(short, long)]
        key: Option<PathBuf>,

        #[clap(short = 'o', name = "name=value")]
        /// Options for DID deactivate operation
        options: Vec<MetadataProperty>,
    },

    #[clap(hide = true)]
    VCIssueCredential(CredentialIssueArgs),
    #[clap(hide = true)]
    VCVerifyCredential(CredentialVerifyArgs),
    /// Subcommand for verifiable credential operations
    #[clap(subcommand)]
    Credential(credential::CredentialCmd),
    #[clap(hide = true)]
    VCIssuePresentation(presentation::PresentationIssueArgs),
    #[clap(hide = true)]
    VCVerifyPresentation(presentation::PresentationVerifyArgs),
    /// Subcommand for verifiable presentation operations
    #[clap(subcommand)]
    Presentation(presentation::PresentationCmd),
    /// Convert JSON-LD to URDNA2015-canonicalized RDF N-Quads
    ToRdfURDNA2015 {
        /// Base IRI
        #[clap(short = 'b', long)]
        base: Option<String>,
        /// IRI for expandContext option
        #[clap(short = 'c', long)]
        expand_context: Option<String>,
        /// Additional values for JSON-LD @context property.
        #[clap(short = 'C', long)]
        more_context_json: Option<String>,
    },
    /*
    /// Revoke Credential
    VCRevokeCredential {},
    */

    /*
    // DIDComm Functionality (???)
    /// Discover a messaging endpoint from a DID which supports DIDComm.
    DIDCommDiscover {},
    /// Send a DIDComm message.
    DIDCommSend {},
    /// Receive a DIDComm message.
    DIDCommReceive {},
    */
}

// An id and optionally a DID
//
// where the id may be present in the DID's DID document
// and may be a DID URL.
//
// Cannot put docstring here because it overwrites help text for did-update subcommands
#[derive(Args, Debug)]
pub struct IdAndDid {
    /// id (URI) of object to add/remove/update in DID document
    id: DIDURL,

    /// DID whose DID document to update. Default: implied from <id>
    ///
    /// Defaults to the DID that is the prefix from the <id> argument.
    #[clap(short, long)]
    did: Option<String>,
}

impl IdAndDid {
    pub fn parse<'a>(self) -> AResult<(&'a dyn DIDMethod, String, DIDURL)> {
        let Self { id, did } = self;
        let method = DID_METHODS
            .get_method(&id.did)
            .map_err(|e| anyhow!("Unable to get DID method: {}", e))?;
        Ok((method.deref(), did.unwrap_or_else(|| id.did.clone()), id))
    }
}

fn parse_service_endpoint(uri_or_object: &str) -> AResult<ServiceEndpoint> {
    let s = uri_or_object.trim();
    if s.starts_with('{') {
        let value = serde_json::from_str(s).context("Parse URI or Object")?;
        Ok(ServiceEndpoint::Map(value))
    } else {
        Ok(ServiceEndpoint::URI(s.to_string()))
    }
}

#[derive(Args, Debug)]
#[clap(rename_all = "camelCase")]
#[clap(group = ArgGroup::new("verification_relationship").multiple(true).required(true))]
pub struct VerificationRelationships {
    /// Allow using this verification method for authentication
    #[clap(short = 'U', long, group = "verification_relationship")]
    pub authentication: bool,

    /// Allow using this verification method for making assertions
    #[clap(short = 'S', long, group = "verification_relationship")]
    pub assertion_method: bool,

    /// Allow using this verification method for key agreement
    #[clap(short = 'K', long, group = "verification_relationship")]
    pub key_agreement: bool,

    /// Allow using this verification method for capability invocation
    #[clap(short = 'I', long, group = "verification_relationship")]
    pub capability_invocation: bool,

    /// Allow using this verification method for capability delegation
    #[clap(short = 'D', long, group = "verification_relationship")]
    pub capability_delegation: bool,
}

impl From<VerificationRelationships> for Vec<VerificationRelationship> {
    fn from(vrels: VerificationRelationships) -> Vec<VerificationRelationship> {
        let mut vrels_vec = vec![];
        let VerificationRelationships {
            authentication,
            assertion_method,
            capability_invocation,
            capability_delegation,
            key_agreement,
        } = vrels;
        if authentication {
            vrels_vec.push(VerificationRelationship::Authentication);
        }
        if assertion_method {
            vrels_vec.push(VerificationRelationship::AssertionMethod);
        }
        if key_agreement {
            vrels_vec.push(VerificationRelationship::KeyAgreement);
        }
        if capability_invocation {
            vrels_vec.push(VerificationRelationship::CapabilityInvocation);
        }
        if capability_delegation {
            vrels_vec.push(VerificationRelationship::CapabilityDelegation);
        }
        vrels_vec
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum DIDUpdateCmd {
    /// Add a verification method to the DID document
    SetVerificationMethod {
        #[clap(flatten)]
        id_and_did: IdAndDid,

        /// Verification method type
        #[clap(short, long)]
        type_: String,

        /// Verification method controller property
        ///
        /// Defaults to the DID this update is for (the <did> option)
        #[clap(short, long)]
        controller: Option<String>,

        #[clap(flatten)]
        verification_relationships: VerificationRelationships,

        #[clap(flatten)]
        public_key: PublicKeyArg,
    },

    /// Add a service to the DID document
    SetService {
        #[clap(flatten)]
        id_and_did: IdAndDid,

        /// Service type
        #[clap(short, long)]
        r#type: Vec<String>,

        /// serviceEndpoint URI or JSON object
        #[clap(short, long, value_parser(parse_service_endpoint))]
        endpoint: Vec<ServiceEndpoint>,
    },

    /// Remove a service endpoint from the DID document
    RemoveService(IdAndDid),

    /// Remove a verification method from the DID document
    RemoveVerificationMethod(IdAndDid),
}

#[derive(Args, Debug, Deserialize)]
#[non_exhaustive]
pub struct ProofOptions {
    // Options as in vc-api (vc-http-api)
    #[clap(env, short, long)]
    pub type_: Option<ProofSuiteType>,
    #[clap(env, short, long)]
    pub verification_method: Option<URI>,
    #[clap(env, short, long)]
    pub proof_purpose: Option<VerificationRelationship>,
    #[clap(env, short, long)]
    pub created: Option<DateTime<Utc>>,
    #[clap(env, short = 'C', long)]
    pub challenge: Option<String>,
    #[clap(env, short, long)]
    pub domain: Option<String>,

    // Non-standard options
    #[clap(env, default_value_t, short = 'f', long)]
    pub proof_format: ProofFormat,
}

/// https://github.com/clap-rs/clap/issues/4349
fn parse_jwk(s: &str) -> Result<JWK, serde_json::Error> {
    serde_json::from_str(s)
}

#[derive(Args, Clone)]
#[clap(group = ArgGroup::new("key_group").multiple(true).required(true))]
pub struct KeyArg {
    #[clap(env, short, long, group = "key_group")]
    key_path: Option<PathBuf>,
    #[clap(
        env,
        short,
        long,
        value_parser(parse_jwk),
        hide_env_values = true,
        conflicts_with = "key_path",
        group = "key_group",
        help = "WARNING: you should not use this through the CLI in a production environment, prefer its environment variable."
    )]
    jwk: Option<JWK>,
    /// Request signature using SSH Agent
    #[clap(short = 'S', long, group = "key_group")]
    ssh_agent: bool,
}

#[derive(Args, Debug)]
#[clap(group = ArgGroup::new("public_key_group").required(true))]
#[clap(rename_all = "camelCase")]
pub struct PublicKeyArg {
    /// Public key JSON Web Key (JWK)
    #[clap(
        short = 'j',
        long,
        group = "public_key_group",
        value_parser(parse_jwk),
        name = "JWK"
    )]
    public_key_jwk: Option<JWK>,

    /// Public key JWK read from file
    #[clap(short = 'k', long, group = "public_key_group", name = "filename")]
    public_key_jwk_path: Option<PathBuf>,

    /// Multibase-encoded public key
    #[clap(short = 'm', long, group = "public_key_group", name = "string")]
    public_key_multibase: Option<String>,

    /// Blockchain Account Id (CAIP-10)
    #[clap(short = 'b', long, group = "public_key_group", name = "account")]
    blockchain_account_id: Option<String>,
}

/// PublicKeyArg as an enum
enum PublicKeyArgEnum {
    PublicKeyJwk(Box<JWK>),
    PublicKeyJwkPath(PathBuf),
    PublicKeyMultibase(String),
    BlockchainAccountId(String),
}

/// PublicKeyArgEnum after file reading.
/// Suitable for use a verification method map.
enum PublicKeyProperty {
    Jwk(Box<JWK>),
    Multibase(String),
    Account(String),
}

/// Convert from struct with options, to enum,
/// until https://github.com/clap-rs/clap/issues/2621
impl TryFrom<PublicKeyArg> for PublicKeyArgEnum {
    type Error = AError;
    fn try_from(pka: PublicKeyArg) -> AResult<PublicKeyArgEnum> {
        Ok(match pka {
            PublicKeyArg {
                public_key_jwk_path: Some(path),
                public_key_jwk: None,
                public_key_multibase: None,
                blockchain_account_id: None,
            } => PublicKeyArgEnum::PublicKeyJwkPath(path),
            PublicKeyArg {
                public_key_jwk_path: None,
                public_key_jwk: Some(jwk),
                public_key_multibase: None,
                blockchain_account_id: None,
            } => PublicKeyArgEnum::PublicKeyJwk(Box::new(jwk)),
            PublicKeyArg {
                public_key_jwk_path: None,
                public_key_jwk: None,
                public_key_multibase: Some(mb),
                blockchain_account_id: None,
            } => PublicKeyArgEnum::PublicKeyMultibase(mb),
            PublicKeyArg {
                public_key_jwk_path: None,
                public_key_jwk: None,
                public_key_multibase: None,
                blockchain_account_id: Some(account),
            } => PublicKeyArgEnum::BlockchainAccountId(account),
            PublicKeyArg {
                public_key_jwk_path: None,
                public_key_jwk: None,
                public_key_multibase: None,
                blockchain_account_id: None,
            } => bail!("Missing public key option"),
            _ => bail!("Only one public key option may be used"),
        })
    }
}

/// Convert public key option to a property for a verification method
impl TryFrom<PublicKeyArgEnum> for PublicKeyProperty {
    type Error = AError;
    fn try_from(pka: PublicKeyArgEnum) -> AResult<PublicKeyProperty> {
        Ok(match pka {
            PublicKeyArgEnum::PublicKeyJwkPath(path) => {
                let key_file = File::open(path).context("Open JWK file")?;
                let key_reader = BufReader::new(key_file);
                let jwk: JWK = serde_json::from_reader(key_reader).context("Read JWK file")?;
                PublicKeyProperty::Jwk(Box::new(jwk.to_public()))
            }
            PublicKeyArgEnum::PublicKeyJwk(jwk) => {
                PublicKeyProperty::Jwk(Box::new(jwk.to_public()))
            }
            PublicKeyArgEnum::PublicKeyMultibase(mb) => PublicKeyProperty::Multibase(mb),
            PublicKeyArgEnum::BlockchainAccountId(account) => PublicKeyProperty::Account(account),
        })
    }
}

fn read_jwk_file_opt(pathbuf_opt: &Option<PathBuf>) -> AResult<Option<JWK>> {
    let pathbuf = match pathbuf_opt {
        Some(pb) => pb,
        None => return Ok(None),
    };
    let key_file = File::open(pathbuf).context("Opening JWK file")?;
    let key_reader = BufReader::new(key_file);
    let jwk = serde_json::from_reader(key_reader).context("Reading JWK file")?;
    Ok(Some(jwk))
}

impl KeyArg {
    fn get_jwk(&self) -> JWK {
        self.get_jwk_opt()
            .expect("Key path or JWK option is required")
    }
    fn get_jwk_opt(&self) -> Option<JWK> {
        match &self.key_path {
            Some(p) => {
                let key_file = File::open(p).unwrap();
                let key_reader = BufReader::new(key_file);
                Some(serde_json::from_reader(key_reader).unwrap())
            }
            None => self.jwk.clone(),
        }
    }
}

impl From<ProofOptions> for LinkedDataProofOptions {
    fn from(options: ProofOptions) -> LinkedDataProofOptions {
        LinkedDataProofOptions {
            type_: options.type_,
            verification_method: options.verification_method,
            proof_purpose: options.proof_purpose,
            created: options.created,
            challenge: options.challenge,
            domain: options.domain,
            checks: None,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Serialize)]
/// Subset of [DID Metadata Structure][metadata] that is just a string property name and string value.
/// [metadata]: https://w3c.github.io/did-core/#metadata-structure
pub struct MetadataProperty {
    pub name: String,
    pub value: Metadata,
}

impl FromStr for MetadataProperty {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, '=');
        let name = parts.next().unwrap_or_default().to_string();
        if let Some(value) = parts.next() {
            Ok(Self {
                name,
                value: Metadata::String(value.to_string()),
            })
        } else {
            Ok(Self {
                name,
                value: Metadata::Boolean(true),
            })
        }
    }
}

fn metadata_properties_to_value(meta_props: Vec<MetadataProperty>) -> Result<Value, Error> {
    use serde_json::map::Entry;
    let mut map = serde_json::Map::new();
    for prop in meta_props {
        let value = serde_json::to_value(prop.value)?;
        match map.entry(prop.name) {
            Entry::Vacant(entry) => {
                entry.insert(value);
            }
            Entry::Occupied(mut entry) => {
                match entry.get_mut() {
                    Value::Null => {
                        entry.insert(value);
                    }
                    Value::Array(ref mut array) => {
                        array.push(value);
                    }
                    _ => {
                        let old_value = entry.get_mut().take();
                        entry.insert(Value::Array(vec![old_value, value]));
                    }
                };
            }
        };
    }
    Ok(Value::Object(map))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn metadata_properties() {
        use serde_json::json;

        // single value - string
        let props = vec![MetadataProperty::from_str("name=value").unwrap()];
        let meta = metadata_properties_to_value(props).unwrap();
        assert_eq!(meta, json!({"name": "value"}));

        // single value - boolean
        let props = vec![MetadataProperty::from_str("name").unwrap()];
        let meta = metadata_properties_to_value(props).unwrap();
        assert_eq!(meta, json!({"name": true}));

        // multiple values
        let props = vec![
            MetadataProperty::from_str("name=value1").unwrap(),
            MetadataProperty::from_str("name=value2").unwrap(),
        ];
        let meta = metadata_properties_to_value(props).unwrap();
        assert_eq!(meta, json!({"name": ["value1", "value2"]}));
    }

    #[test]
    fn verify_app() {
        DIDKit::command().debug_assert()
    }
}

fn get_ssh_agent_sock() -> String {
    use std::env::VarError;
    match std::env::var("SSH_AUTH_SOCK") {
        Ok(string) => string,
        Err(VarError::NotPresent) => {
            eprintln!(
                r#"didkit: missing SSH_AUTH_SOCK environmental variable for SSH Agent usage.
To use DIDKit with SSH Agent, ssh-agent must be running and $SSH_AUTH_SOCK
set. For more info, see the manual for ssh-agent(1) and ssh-add(1).
"#
            );
            std::process::exit(1);
        }
        Err(VarError::NotUnicode(_)) => panic!("Unable to parse SSH_AUTH_SOCK"),
    }
}

#[tokio::main]
async fn main() -> AResult<()> {
    let opt = DIDKit::parse();
    let ssh_agent_sock;

    match opt.command {
        DIDKitCmd::GenerateEd25519Key => key::generate(key::KeyGenerateCmd::Ed25519).await.unwrap(),
        DIDKitCmd::Key(cmd) => key::cli(cmd).await.unwrap(),
        DIDKitCmd::KeyToDIDKey(key) => {
            // Deprecated in favor of KeyToDID
            eprintln!("didkit: use key-to-did instead of key-to-did-key");
            key::to_did(key::KeyToDIDArgs {
                method_pattern: "key".to_string(),
                key,
            })
            .await
            .unwrap();
        }
        DIDKitCmd::KeyToDID(args) => key::to_did(args).await.unwrap(),
        DIDKitCmd::KeyToVerificationMethod(args) => key::to_vm(args).await.unwrap(),
        DIDKitCmd::SshPkToJwk(args) => key::from_ssh(args).await.unwrap(),

        DIDKitCmd::VCIssueCredential(args) => credential::issue(args).await.unwrap(),
        DIDKitCmd::VCVerifyCredential(args) => credential::verify(args).await.unwrap(),
        DIDKitCmd::Credential(cmd) => credential::cli(cmd).await.unwrap(),

        DIDKitCmd::VCIssuePresentation(args) => presentation::issue(args).await.unwrap(),
        DIDKitCmd::VCVerifyPresentation(args) => presentation::verify(args).await.unwrap(),
        DIDKitCmd::Presentation(cmd) => presentation::cli(cmd).await.unwrap(),

        DIDKitCmd::ToRdfURDNA2015 {
            base,
            expand_context,
            more_context_json,
        } => {
            let mut loader = StaticLoader;
            let expand_context = if let Some(m_c) = more_context_json {
                if let Some(e_c) = expand_context {
                    Some(
                        serde_json::to_string(&json!([
                            e_c,
                            serde_json::from_str::<serde_json::Value>(&m_c).unwrap()
                        ]))
                        .unwrap(),
                    )
                } else {
                    Some(m_c)
                }
            } else {
                expand_context
            };
            let mut reader = BufReader::new(stdin());
            let mut json = String::new();
            reader.read_to_string(&mut json).unwrap();
            let json = jsonld::syntax::to_value_with(
                serde_json::from_str::<serde_json::Value>(&json).unwrap(),
                Default::default,
            )
            .unwrap();
            let expand_context = expand_context.map(|c| parse_ld_context(&c).unwrap());
            // Implementation of `ssi::jsonld::json_to_dataset`
            let options = jsonld::Options {
                base: base.map(|b| IriBuf::from_string(b).unwrap()),
                expand_context,
                ..Default::default()
            };
            let doc = jsonld::RemoteDocument::new(None, None, json);
            let mut generator = rdf_types::generator::Blank::new_with_prefix("b".to_string())
                .with_default_metadata();
            let mut to_rdf = doc
                .to_rdf_using(&mut generator, &mut loader, options)
                .await
                .map_err(Box::new)
                .unwrap();
            let dataset: rdf::DataSet = to_rdf
                .cloned_quads()
                .map(|q| q.map_predicate(|p| p.into_iri().unwrap()))
                .collect();
            let dataset_normalized = ssi::urdna2015::normalize(dataset.quads().map(Into::into));
            let normalized = dataset_normalized.into_nquads();
            stdout().write_all(normalized.as_bytes()).unwrap();
        }

        DIDKitCmd::DIDCreate {
            method,
            verification_key,
            update_key,
            recovery_key,
            options,
        } => {
            let method = DID_METHODS
                .get(&method)
                .ok_or(anyhow!("Unable to get DID method"))?;
            let verification_key = read_jwk_file_opt(&verification_key)
                .context("Read verification key for DID Create")?;
            let update_key =
                read_jwk_file_opt(&update_key).context("Read update key for DID Create")?;
            let recovery_key =
                read_jwk_file_opt(&recovery_key).context("Read recovery key for DID Create")?;
            let options =
                metadata_properties_to_value(options).context("Parse options for DID Create")?;
            let options = serde_json::from_value(options).context("Unable to convert options")?;

            let tx = method
                .create(DIDCreate {
                    recovery_key,
                    update_key,
                    verification_key,
                    options,
                })
                .context("DID Create failed")?;
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer_pretty(stdout_writer, &tx).unwrap();
            println!();
        }

        DIDKitCmd::DIDFromTx => {
            let stdin_reader = BufReader::new(stdin());
            let tx: DIDMethodTransaction = serde_json::from_reader(stdin_reader).unwrap();
            let method = DID_METHODS
                .get(&tx.did_method)
                .ok_or(anyhow!("Unable to get DID method"))?;
            let did = method
                .did_from_transaction(tx)
                .context("Get DID from transaction")?;
            println!("{did}");
        }

        DIDKitCmd::DIDSubmitTx => {
            let stdin_reader = BufReader::new(stdin());
            let tx: DIDMethodTransaction = serde_json::from_reader(stdin_reader).unwrap();
            let method = DID_METHODS
                .get(&tx.did_method)
                .ok_or(anyhow!("Unable to get DID method"))?;
            let result = method
                .submit_transaction(tx)
                .await
                .context("Submit DID transaction")?;
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer_pretty(stdout_writer, &result).unwrap();
            println!();
        }

        DIDKitCmd::DIDUpdate {
            new_update_key,
            update_key,
            options,
            cmd,
        } => {
            let new_update_key =
                read_jwk_file_opt(&new_update_key).context("Read new update key for DID update")?;
            let update_key =
                read_jwk_file_opt(&update_key).context("Read update key for DID update")?;
            let options =
                metadata_properties_to_value(options).context("Parse options for DID update")?;
            let options = serde_json::from_value(options).context("Unable to convert options")?;

            let (did, method, operation) = match cmd {
                DIDUpdateCmd::SetVerificationMethod {
                    id_and_did,
                    type_,
                    controller,
                    public_key,
                    verification_relationships,
                } => {
                    let (method, did, id) = id_and_did
                        .parse()
                        .context("Parse id/DID for set-verification-method subcommand")?;
                    let pk_enum =
                        PublicKeyArgEnum::try_from(public_key).context("Read public key option")?;
                    let public_key =
                        PublicKeyProperty::try_from(pk_enum).context("Read public key property")?;
                    let purposes = verification_relationships.into();
                    let controller = controller.unwrap_or_else(|| did.clone());
                    let mut vmm = ssi::did::VerificationMethodMap {
                        id: id.to_string(),
                        type_,
                        controller,
                        ..Default::default()
                    };
                    match public_key {
                        PublicKeyProperty::Jwk(jwk) => vmm.public_key_jwk = Some(*jwk),
                        PublicKeyProperty::Multibase(mb) => {
                            let mut ps = std::collections::BTreeMap::<String, Value>::default();
                            ps.insert("publicKeyMultibase".to_string(), Value::String(mb));
                            vmm.property_set = Some(ps);
                        }
                        PublicKeyProperty::Account(account) => {
                            vmm.blockchain_account_id = Some(account);
                        }
                    }
                    let op = DIDDocumentOperation::SetVerificationMethod { vmm, purposes };
                    (did, method, op)
                }
                DIDUpdateCmd::RemoveVerificationMethod(id_and_did) => {
                    let (method, did, id) = id_and_did.parse().context(
                        "Unable to parse id/DID for remove-verification-method subcommand",
                    )?;
                    let op = DIDDocumentOperation::RemoveVerificationMethod(id);
                    (did, method, op)
                }
                DIDUpdateCmd::SetService {
                    id_and_did,
                    endpoint,
                    r#type,
                } => {
                    let (method, did, id) = id_and_did
                        .parse()
                        .context("Parse id/DID for set-verification-method subcommand")?;
                    let service_endpoint = match endpoint.len() {
                        0 => None,
                        1 => endpoint.into_iter().next().map(OneOrMany::One),
                        _ => Some(OneOrMany::Many(endpoint)),
                    };
                    let type_ = match r#type.len() {
                        1 => r#type
                            .into_iter()
                            .next()
                            .map(OneOrMany::One)
                            .ok_or(anyhow!("Missing service type"))?,

                        _ => OneOrMany::Many(r#type),
                    };
                    let service = Service {
                        id: id.to_string(),
                        type_,
                        service_endpoint,
                        property_set: None,
                    };
                    let op = DIDDocumentOperation::SetService(service);
                    (did, method, op)
                }
                DIDUpdateCmd::RemoveService(id_and_did) => {
                    let (method, did, id) = id_and_did
                        .parse()
                        .context("Parse id/DID for set-verification-method subcommand")?;
                    let op = DIDDocumentOperation::RemoveService(id);
                    (did, method, op)
                }
            };
            let tx = method
                .update(DIDUpdate {
                    did,
                    update_key,
                    new_update_key,
                    operation,
                    options,
                })
                .context("DID Update failed")?;
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer_pretty(stdout_writer, &tx).unwrap();
            println!();
        }

        DIDKitCmd::DIDRecover {
            did,
            new_verification_key,
            new_update_key,
            new_recovery_key,
            recovery_key,
            options,
        } => {
            let method = DID_METHODS
                .get_method(&did)
                .map_err(|e| anyhow!("Unable to get DID method: {}", e))?;
            let new_verification_key = read_jwk_file_opt(&new_verification_key)
                .context("Read new signing key for DID recovery")?;
            let new_update_key = read_jwk_file_opt(&new_update_key)
                .context("Read new update key for DID recovery")?;
            let new_recovery_key = read_jwk_file_opt(&new_recovery_key)
                .context("Read new recovery key for DID recovery")?;
            let recovery_key =
                read_jwk_file_opt(&recovery_key).context("Read recovery key for DID recovery")?;
            let options =
                metadata_properties_to_value(options).context("Parse options for DID recovery")?;
            let options = serde_json::from_value(options).context("Unable to convert options")?;

            let tx = method
                .recover(DIDRecover {
                    did: did.clone(),
                    recovery_key,
                    new_recovery_key,
                    new_update_key,
                    new_verification_key,
                    options,
                })
                .context("DID Recover failed")?;
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer_pretty(stdout_writer, &tx).unwrap();
            println!();
        }

        DIDKitCmd::DIDDeactivate { did, key, options } => {
            let method = DID_METHODS
                .get_method(&did)
                .map_err(|e| anyhow!("Unable to get DID method: {}", e))?;
            let key = read_jwk_file_opt(&key).context("Read key for DID deactivation")?;
            let options = metadata_properties_to_value(options)
                .context("Parse options for DID deactivation")?;
            let options = serde_json::from_value(options).context("Unable to convert options")?;

            let tx = method
                .deactivate(DIDDeactivate {
                    did: did.clone(),
                    key,
                    options,
                })
                .context("DID deactivation failed")?;
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer_pretty(stdout_writer, &tx).unwrap();
            println!();
        }

        DIDKitCmd::DIDResolve {
            did,
            with_metadata,
            input_metadata,
            resolver_options,
        } => {
            let resolver = resolver_options.to_resolver();
            let res_input_meta_value = metadata_properties_to_value(input_metadata).unwrap();
            let res_input_meta: ResolutionInputMetadata =
                serde_json::from_value(res_input_meta_value).unwrap();
            if with_metadata {
                let (res_meta, doc_opt, doc_meta_opt) =
                    resolver.resolve(&did, &res_input_meta).await;
                let error = res_meta.error.is_some();
                let result = ResolutionResult {
                    did_document: doc_opt,
                    did_resolution_metadata: Some(res_meta),
                    did_document_metadata: doc_meta_opt,
                    ..Default::default()
                };
                let stdout_writer = BufWriter::new(stdout());
                serde_json::to_writer_pretty(stdout_writer, &result).unwrap();
                if error {
                    std::process::exit(2);
                }
            } else {
                let (res_meta, doc_data, _doc_meta_opt) =
                    resolver.resolve_representation(&did, &res_input_meta).await;
                if let Some(err) = res_meta.error {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
                stdout().write_all(&doc_data).unwrap();
            }
        }

        DIDKitCmd::DIDDereference {
            did_url,
            with_metadata,
            input_metadata,
            resolver_options,
        } => {
            let resolver = resolver_options.to_resolver();
            let deref_input_meta_value = metadata_properties_to_value(input_metadata).unwrap();
            let deref_input_meta: DereferencingInputMetadata =
                serde_json::from_value(deref_input_meta_value).unwrap();
            let stdout_writer = BufWriter::new(stdout());
            let (deref_meta, content, content_meta) =
                dereference(&resolver, &did_url, &deref_input_meta).await;
            if with_metadata {
                let result = json!([deref_meta, content, content_meta]);
                serde_json::to_writer_pretty(stdout_writer, &result).unwrap();
                if deref_meta.error.is_some() {
                    std::process::exit(2);
                }
            } else {
                if let Some(err) = deref_meta.error {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
                let content_vec = content.into_vec().unwrap();
                stdout().write_all(&content_vec).unwrap();
            }
        }

        DIDKitCmd::DIDAuth {
            key,
            holder,
            proof_options,
            resolver_options,
        } => {
            let resolver = resolver_options.to_resolver();
            let mut context_loader = ssi::jsonld::ContextLoader::default();
            let mut presentation = VerifiablePresentation {
                holder: Some(ssi::vc::URI::String(holder)),
                ..Default::default()
            };
            let proof_format = proof_options.proof_format.clone();
            let jwk_opt: Option<JWK> = key.get_jwk_opt();
            let ssh_agent_sock_opt = if key.ssh_agent {
                ssh_agent_sock = get_ssh_agent_sock();
                Some(&ssh_agent_sock[..])
            } else {
                None
            };
            let options = LinkedDataProofOptions::from(proof_options);
            match proof_format {
                ProofFormat::JWT => {
                    if ssh_agent_sock_opt.is_some() {
                        todo!("ssh-agent for JWT not implemented");
                    }
                    let jwt = presentation
                        .generate_jwt(jwk_opt.as_ref(), &options, &resolver)
                        .await
                        .unwrap();
                    print!("{jwt}");
                }
                ProofFormat::LDP => {
                    let proof = generate_proof(
                        &presentation,
                        jwk_opt.as_ref(),
                        options,
                        &resolver,
                        &mut context_loader,
                        ssh_agent_sock_opt,
                    )
                    .await
                    .unwrap();
                    presentation.add_proof(proof);
                    let stdout_writer = BufWriter::new(stdout());
                    serde_json::to_writer(stdout_writer, &presentation).unwrap();
                }
                _ => {
                    panic!("Unexpected proof format: {:?}", proof_format);
                }
            }
        }
    }
    Ok(())
}
