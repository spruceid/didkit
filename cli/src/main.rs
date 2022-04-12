use std::convert::TryFrom;
use std::fs::File;
use std::io::{stdin, stdout, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Error as AError, Result as AResult};
use chrono::prelude::*;
use clap::{AppSettings, ArgGroup, Parser, StructOpt};
use serde::Serialize;
use serde_json::Value;
use sshkeys::PublicKey;

use did_method_key::DIDKey;
use didkit::generate_proof;
use didkit::{
    dereference, get_verification_method, runtime, DIDCreate, DIDDeactivate, DIDDocumentOperation,
    DIDMethod, DIDRecover, DIDResolver, DIDUpdate, DereferencingInputMetadata, Error,
    LinkedDataProofOptions, Metadata, ProofFormat, ProofPurpose, ResolutionInputMetadata,
    ResolutionResult, Source, VerifiableCredential, VerifiablePresentation, DIDURL, DID_METHODS,
    JWK, URI,
};
use didkit_cli::opts::ResolverOptions;
use ssi::did::{DIDMethodTransaction, Service, ServiceEndpoint, VerificationRelationship};
use ssi::one_or_many::OneOrMany;

#[derive(StructOpt, Debug)]
pub enum DIDKit {
    /// Generate and output a Ed25519 keypair in JWK format
    #[clap(setting(clap::AppSettings::Hidden))]
    GenerateEd25519Key,
    /// Subcommand for keypair operations
    #[clap(subcommand)]
    Key(KeyCmd),
    /// Output a did:key DID for a JWK. Deprecated in favor of key-to-did.
    #[clap(setting = AppSettings::Hidden)]
    KeyToDIDKey {
        #[clap(flatten)]
        key: KeyArg,
    },
    /// Output a DID for a given JWK according to the provided DID method name or pattern
    ///
    /// Deterministically generate a DID from a public key JWK, for a DID method
    /// that support this functionality.
    ///
    /// The DID method to use may be provided in the `method-pattern` argument. The default is
    /// "key", corresponding to did:key.
    ///
    /// For DID methods that have multiple ways of representing a key, `method-pattern` is
    /// method-specific but typically is a prefix, for example "pkh:tz" to generate a DID that
    /// begins with `did:pkh:tz`.
    KeyToDID {
        /// DID method name or pattern. e.g. `key`, `tz`, or `pkh:tz`
        #[clap(default_value = "key")]
        method_pattern: String,
        #[clap(flatten)]
        key: KeyArg,
    },
    /// Output a verificationMethod DID URL for a JWK and DID method name/pattern
    KeyToVerificationMethod {
        /// DID method id or pattern. e.g. `key`, `tz`, or `pkh:tz`
        method_pattern: Option<String>,
        #[clap(flatten)]
        key: KeyArg,
    },
    /// Convert a SSH public key to a JWK
    SshPkToJwk {
        #[clap(parse(try_from_str=PublicKey::from_string))]
        /// SSH Public Key
        ssh_pk: PublicKey,
    },

    // DID Functionality
    /// Create new DID Document.
    // See also: https://identity.foundation/did-registration/#create
    //           (method), jobId, options, secret, didDocument
    DIDCreate {
        /// DID method name
        method: String,

        /// JWK file for default verification method
        #[clap(short, long, parse(from_os_str))]
        verification_key: Option<PathBuf>,

        /// JWK file for DID Update operations
        #[clap(short, long, parse(from_os_str))]
        update_key: Option<PathBuf>,

        /// JWK file for DID Recovery and/or Deactivate operations
        #[clap(short, long, parse(from_os_str))]
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
        #[clap(short = 'u', long, parse(from_os_str))]
        new_update_key: Option<PathBuf>,

        /// JWK file for performing this DID update operation.
        #[clap(short = 'U', long, parse(from_os_str))]
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
        #[clap(short = 'v', long, parse(from_os_str))]
        new_verification_key: Option<PathBuf>,

        /// New JWK file for DID Update operations
        #[clap(short = 'u', long, parse(from_os_str))]
        new_update_key: Option<PathBuf>,

        /// New JWK file for DID Recovery and/or Deactivate operations
        #[clap(short = 'r', long, parse(from_os_str))]
        new_recovery_key: Option<PathBuf>,

        /// JWK file for performing this DID recover operation.
        #[clap(short = 'R', long, parse(from_os_str))]
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
        #[clap(short, long, parse(from_os_str))]
        key: Option<PathBuf>,

        #[clap(short = 'o', name = "name=value")]
        /// Options for DID deactivate operation
        options: Vec<MetadataProperty>,
    },

    /*
    /// Create a Signed IETF JSON Patch to update a DID document.
    DIDPatch {},
    */
    // VC Functionality
    /// Issue Credential
    VCIssueCredential {
        #[clap(flatten)]
        key: KeyArg,
        #[clap(flatten)]
        proof_options: ProofOptions,
        #[clap(flatten)]
        resolver_options: ResolverOptions,
    },
    /// Verify Credential
    VCVerifyCredential {
        #[clap(flatten)]
        proof_options: ProofOptions,
        #[clap(flatten)]
        resolver_options: ResolverOptions,
    },
    /// Issue Presentation
    VCIssuePresentation {
        #[clap(flatten)]
        key: KeyArg,
        #[clap(flatten)]
        proof_options: ProofOptions,
        #[clap(flatten)]
        resolver_options: ResolverOptions,
    },
    /// Verify Presentation
    VCVerifyPresentation {
        #[clap(flatten)]
        resolver_options: ResolverOptions,
        #[clap(flatten)]
        proof_options: ProofOptions,
    },
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
#[derive(StructOpt, Debug)]
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
        Ok((*method, did.unwrap_or_else(|| id.did.clone()), id))
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

#[derive(StructOpt, Debug)]
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

#[derive(StructOpt, Debug)]
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
        #[clap(short, long, parse(try_from_str = parse_service_endpoint))]
        endpoint: Vec<ServiceEndpoint>,
    },

    /// Remove a service endpoint from the DID document
    RemoveService(IdAndDid),

    /// Remove a verification method from the DID document
    RemoveVerificationMethod(IdAndDid),
}

#[derive(StructOpt, Debug)]
#[non_exhaustive]
pub struct ProofOptions {
    // Options as in vc-api (vc-http-api)
    #[clap(env, short, long)]
    pub type_: Option<String>,
    #[clap(env, short, long)]
    pub verification_method: Option<URI>,
    #[clap(env, short, long)]
    pub proof_purpose: Option<ProofPurpose>,
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

#[derive(StructOpt, Debug)]
#[clap(group = ArgGroup::new("key_group").multiple(true).required(true))]
pub struct KeyArg {
    #[clap(env, short, long, parse(from_os_str), group = "key_group")]
    key_path: Option<PathBuf>,
    #[clap(
        env,
        short,
        long,
        parse(try_from_str = serde_json::from_str),
        hide_env_values = true,
        conflicts_with = "key-path",
        group = "key_group",
        help = "WARNING: you should not use this through the CLI in a production environment, prefer its environment variable."
    )]
    jwk: Option<JWK>,
    /// Request signature using SSH Agent
    #[clap(short = 'S', long, group = "key_group")]
    ssh_agent: bool,
}

#[derive(StructOpt, Debug)]
#[clap(group = ArgGroup::new("public_key_group").required(true))]
#[clap(rename_all = "camelCase")]
pub struct PublicKeyArg {
    /// Public key JSON Web Key (JWK)
    #[clap(short = 'j', long, group = "public_key_group", parse(try_from_str = serde_json::from_str), name = "JWK")]
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
    PublicKeyJwk(JWK),
    PublicKeyJwkPath(PathBuf),
    PublicKeyMultibase(String),
    BlockchainAccountId(String),
}

/// PublicKeyArgEnum after file reading.
/// Suitable for use a verification method map.
enum PublicKeyProperty {
    JWK(JWK),
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
            } => PublicKeyArgEnum::PublicKeyJwk(jwk),
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
                PublicKeyProperty::JWK(jwk.to_public())
            }
            PublicKeyArgEnum::PublicKeyJwk(jwk) => PublicKeyProperty::JWK(jwk.to_public()),
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

#[derive(StructOpt, Debug)]
pub enum KeyCmd {
    /// Generate and output a keypair in JWK format
    #[clap(subcommand)]
    Generate(KeyGenerateCmd),
}

#[derive(StructOpt, Debug)]
pub enum KeyGenerateCmd {
    /// Generate and output a Ed25519 keypair in JWK format
    Ed25519,
    /// Generate and output a K-256 keypair in JWK format
    Secp256k1,
    /// Generate and output a P-256 keypair in JWK format
    Secp256r1,
}

#[derive(Debug, Serialize)]
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
        use clap::IntoApp;
        DIDKit::into_app().debug_assert()
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

fn main() -> AResult<()> {
    let rt = runtime::get().unwrap();
    let opt = DIDKit::parse();
    let ssh_agent_sock;

    match opt {
        DIDKit::GenerateEd25519Key => {
            let jwk = JWK::generate_ed25519().unwrap();
            let jwk_str = serde_json::to_string(&jwk).unwrap();
            println!("{}", jwk_str);
        }

        DIDKit::Key(cmd) => match cmd {
            KeyCmd::Generate(cmd_generate) => {
                let jwk_str = match cmd_generate {
                    KeyGenerateCmd::Ed25519 => {
                        let jwk = JWK::generate_ed25519().unwrap();
                        serde_json::to_string(&jwk).unwrap()
                    }
                    KeyGenerateCmd::Secp256k1 => {
                        let jwk = JWK::generate_secp256k1().unwrap();
                        serde_json::to_string(&jwk).unwrap()
                    }
                    KeyGenerateCmd::Secp256r1 => {
                        let jwk = JWK::generate_p256().unwrap();
                        serde_json::to_string(&jwk).unwrap()
                    }
                };
                println!("{}", jwk_str);
            }
        },

        DIDKit::KeyToDIDKey { key } => {
            // Deprecated in favor of KeyToDID
            eprintln!("didkit: use key-to-did instead of key-to-did-key");
            let jwk = key.get_jwk();
            let did = DIDKey
                .generate(&Source::Key(&jwk))
                .ok_or(Error::UnableToGenerateDID)
                .unwrap();
            println!("{}", did);
        }

        DIDKit::KeyToDID {
            method_pattern,
            key,
        } => {
            let jwk = key.get_jwk();
            let did = DID_METHODS
                .generate(&Source::KeyAndPattern(&jwk, &method_pattern))
                .ok_or(Error::UnableToGenerateDID)
                .unwrap();
            println!("{}", did);
        }

        DIDKit::SshPkToJwk { ssh_pk } => {
            let jwk = ssi::ssh::ssh_pkk_to_jwk(&ssh_pk.kind).unwrap();
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer_pretty(stdout_writer, &jwk).unwrap();
        }

        DIDKit::KeyToVerificationMethod {
            method_pattern,
            key,
        } => {
            let method_pattern = match method_pattern {
                Some(pattern) => pattern,
                None => {
                    eprintln!(
                        "didkit: key-to-verification-method should be used with method pattern option"
                    );
                    "key".to_string()
                }
            };
            let jwk = key.get_jwk();
            let did = DID_METHODS
                .generate(&Source::KeyAndPattern(&jwk, &method_pattern))
                .ok_or(Error::UnableToGenerateDID)
                .unwrap();
            let did_resolver = DID_METHODS.to_resolver();
            let vm = rt
                .block_on(get_verification_method(&did, did_resolver))
                .ok_or(Error::UnableToGetVerificationMethod)
                .unwrap();
            println!("{}", vm);
        }

        DIDKit::VCIssueCredential {
            key,
            resolver_options,
            proof_options,
        } => {
            let resolver = resolver_options.to_resolver();
            let credential_reader = BufReader::new(stdin());
            let mut credential: VerifiableCredential =
                serde_json::from_reader(credential_reader).unwrap();
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
                    let jwt = rt
                        .block_on(credential.generate_jwt(jwk_opt.as_ref(), &options, &resolver))
                        .unwrap();
                    print!("{}", jwt);
                }
                ProofFormat::LDP => {
                    let proof = rt
                        .block_on(generate_proof(
                            &credential,
                            jwk_opt.as_ref(),
                            options,
                            &resolver,
                            ssh_agent_sock_opt,
                        ))
                        .unwrap();
                    credential.add_proof(proof);
                    let stdout_writer = BufWriter::new(stdout());
                    serde_json::to_writer(stdout_writer, &credential).unwrap();
                }
                _ => {
                    panic!("Unknown proof format: {:?}", proof_format);
                }
            }
        }

        DIDKit::VCVerifyCredential {
            proof_options,
            resolver_options,
        } => {
            let resolver = resolver_options.to_resolver();
            let mut credential_reader = BufReader::new(stdin());
            let proof_format = proof_options.proof_format.clone();
            let options = LinkedDataProofOptions::from(proof_options);
            let result = match proof_format {
                ProofFormat::JWT => {
                    let mut jwt = String::new();
                    credential_reader.read_to_string(&mut jwt).unwrap();
                    rt.block_on(VerifiableCredential::verify_jwt(
                        &jwt,
                        Some(options),
                        &resolver,
                    ))
                }
                ProofFormat::LDP => {
                    let credential: VerifiableCredential =
                        serde_json::from_reader(credential_reader).unwrap();
                    credential.validate_unsigned().unwrap();
                    rt.block_on(credential.verify(Some(options), &resolver))
                }
                _ => {
                    panic!("Unknown proof format: {:?}", proof_format);
                }
            };

            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer(stdout_writer, &result).unwrap();
            if result.errors.len() > 0 {
                std::process::exit(2);
            }
        }

        DIDKit::VCIssuePresentation {
            key,
            resolver_options,
            proof_options,
        } => {
            let resolver = resolver_options.to_resolver();
            let presentation_reader = BufReader::new(stdin());
            let mut presentation: VerifiablePresentation =
                serde_json::from_reader(presentation_reader).unwrap();

            let jwk_opt: Option<JWK> = key.get_jwk_opt();
            let ssh_agent_sock_opt = if key.ssh_agent {
                ssh_agent_sock = get_ssh_agent_sock();
                Some(&ssh_agent_sock[..])
            } else {
                None
            };
            let proof_format = proof_options.proof_format.clone();
            let options = LinkedDataProofOptions::from(proof_options);
            match proof_format {
                ProofFormat::JWT => {
                    if ssh_agent_sock_opt.is_some() {
                        todo!("ssh-agent for JWT not implemented");
                    }
                    let jwt = rt
                        .block_on(presentation.generate_jwt(jwk_opt.as_ref(), &options, &resolver))
                        .unwrap();
                    print!("{}", jwt);
                }
                ProofFormat::LDP => {
                    let proof = rt
                        .block_on(generate_proof(
                            &presentation,
                            jwk_opt.as_ref(),
                            options,
                            &resolver,
                            ssh_agent_sock_opt,
                        ))
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

        DIDKit::VCVerifyPresentation {
            proof_options,
            resolver_options,
        } => {
            let resolver = resolver_options.to_resolver();
            let mut presentation_reader = BufReader::new(stdin());
            let proof_format = proof_options.proof_format.clone();
            let options = LinkedDataProofOptions::from(proof_options);
            let result = match proof_format {
                ProofFormat::JWT => {
                    let mut jwt = String::new();
                    presentation_reader.read_to_string(&mut jwt).unwrap();
                    rt.block_on(VerifiablePresentation::verify_jwt(
                        &jwt,
                        Some(options),
                        &resolver,
                    ))
                }
                ProofFormat::LDP => {
                    let presentation: VerifiablePresentation =
                        serde_json::from_reader(presentation_reader).unwrap();
                    presentation.validate_unsigned().unwrap();
                    rt.block_on(presentation.verify(Some(options), &resolver))
                }
                _ => {
                    panic!("Unexpected proof format: {:?}", proof_format);
                }
            };
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer(stdout_writer, &result).unwrap();
            if result.errors.len() > 0 {
                std::process::exit(2);
            }
        }

        DIDKit::ToRdfURDNA2015 {
            base,
            expand_context,
            more_context_json,
        } => {
            use ssi::jsonld::{json_to_dataset, JsonLdOptions, StaticLoader};
            let mut loader = StaticLoader;
            let mut reader = BufReader::new(stdin());
            let mut json = String::new();
            reader.read_to_string(&mut json).unwrap();
            let options = JsonLdOptions {
                base,
                expand_context,
                ..Default::default()
            };
            let dataset = rt
                .block_on(json_to_dataset(
                    &json,
                    more_context_json.as_ref(),
                    false,
                    Some(&options),
                    &mut loader,
                ))
                .unwrap();
            let dataset_normalized = ssi::urdna2015::normalize(&dataset).unwrap();
            let normalized = dataset_normalized.to_nquads().unwrap();
            stdout().write_all(normalized.as_bytes()).unwrap();
        }

        DIDKit::DIDCreate {
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
            println!("");
        }

        DIDKit::DIDFromTx => {
            let stdin_reader = BufReader::new(stdin());
            let tx: DIDMethodTransaction = serde_json::from_reader(stdin_reader).unwrap();
            let method = DID_METHODS
                .get(&tx.did_method)
                .ok_or(anyhow!("Unable to get DID method"))?;
            let did = method
                .did_from_transaction(tx)
                .context("Get DID from transaction")?;
            println!("{}", did);
        }

        DIDKit::DIDSubmitTx => {
            let stdin_reader = BufReader::new(stdin());
            let tx: DIDMethodTransaction = serde_json::from_reader(stdin_reader).unwrap();
            let method = DID_METHODS
                .get(&tx.did_method)
                .ok_or(anyhow!("Unable to get DID method"))?;
            let result = rt
                .block_on(method.submit_transaction(tx))
                .context("Submit DID transaction")?;
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer_pretty(stdout_writer, &result).unwrap();
            println!("");
        }

        DIDKit::DIDUpdate {
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
                        PublicKeyProperty::JWK(jwk) => vmm.public_key_jwk = Some(jwk),
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
                    did: did.clone(),
                    update_key,
                    new_update_key,
                    operation,
                    options,
                })
                .context("DID Update failed")?;
            let stdout_writer = BufWriter::new(stdout());
            serde_json::to_writer_pretty(stdout_writer, &tx).unwrap();
            println!("");
        }

        DIDKit::DIDRecover {
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
            println!("");
        }

        DIDKit::DIDDeactivate { did, key, options } => {
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
            println!("");
        }

        DIDKit::DIDResolve {
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
                    rt.block_on(resolver.resolve(&did, &res_input_meta));
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
                    rt.block_on(resolver.resolve_representation(&did, &res_input_meta));
                if let Some(err) = res_meta.error {
                    eprintln!("{}", err);
                    std::process::exit(2);
                }
                stdout().write_all(&doc_data).unwrap();
            }
        }

        DIDKit::DIDDereference {
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
                rt.block_on(dereference(&resolver, &did_url, &deref_input_meta));
            if with_metadata {
                use serde_json::json;
                let result = json!([deref_meta, content, content_meta]);
                serde_json::to_writer_pretty(stdout_writer, &result).unwrap();
                if deref_meta.error.is_some() {
                    std::process::exit(2);
                }
            } else {
                if let Some(err) = deref_meta.error {
                    eprintln!("{}", err);
                    std::process::exit(2);
                }
                let content_vec = content.into_vec().unwrap();
                stdout().write_all(&content_vec).unwrap();
            }
        }

        DIDKit::DIDAuth {
            key,
            holder,
            proof_options,
            resolver_options,
        } => {
            let resolver = resolver_options.to_resolver();
            let mut presentation = VerifiablePresentation::default();
            presentation.holder = Some(ssi::vc::URI::String(holder));
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
                    let jwt = rt
                        .block_on(presentation.generate_jwt(jwk_opt.as_ref(), &options, &resolver))
                        .unwrap();
                    print!("{}", jwt);
                }
                ProofFormat::LDP => {
                    let proof = rt
                        .block_on(generate_proof(
                            &presentation,
                            jwk_opt.as_ref(),
                            options,
                            &resolver,
                            ssh_agent_sock_opt,
                        ))
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
