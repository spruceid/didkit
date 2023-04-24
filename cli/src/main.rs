use std::{convert::TryFrom, fs::File, io::BufReader, ops::Deref, path::PathBuf, str::FromStr};

use anyhow::{anyhow, bail, Context, Error as AError, Result as AResult};
use chrono::prelude::*;
use clap::{ArgGroup, Args, Parser, Subcommand};
use credential::{CredentialIssueArgs, CredentialVerifyArgs};
use didkit::ssi::ldp::ProofSuiteType;
use didkit::{
    ssi::did::ServiceEndpoint, DIDMethod, Error, LinkedDataProofOptions, Metadata, ProofFormat,
    VerificationRelationship, DIDURL, DID_METHODS, JWK, URI,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod credential;
mod did;
mod jsonld;
mod key;
mod opts;
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
    /// Subcommand for DID operations
    #[clap(subcommand)]
    Did(did::DidCmd),
    #[clap(hide = true)]
    DIDCreate(did::DidCreateArgs),
    #[clap(hide = true)]
    DIDFromTx,
    #[clap(hide = true)]
    DIDSubmitTx,
    #[clap(hide = true)]
    DIDUpdate(did::DidUpdateArgs),
    #[clap(hide = true)]
    DIDRecover(did::DidRecoverArgs),
    #[clap(hide = true)]
    DIDResolve(did::DidResolveArgs),
    #[clap(hide = true)]
    DIDDereference(did::DidDereferenceArgs),
    #[clap(hide = true)]
    DIDAuth(did::DidAuthenticateArgs),
    #[clap(hide = true)]
    DIDDeactivate(did::DidDeactivateArgs),
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
    /// Subcommand for JSON-LD operations
    #[clap(subcommand)]
    Jsonld(jsonld::JsonldCmd),
    #[clap(hide = true)]
    ToRdfURDNA2015(jsonld::JsonldToRDFURDNAArgs),
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
    tracing_subscriber::fmt::init();

    let opt = DIDKit::parse();
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
        DIDKitCmd::Jsonld(cmd) => jsonld::cli(cmd).await.unwrap(),
        DIDKitCmd::ToRdfURDNA2015(args) => jsonld::to_rdfurdna(args).await.unwrap(),
        DIDKitCmd::Did(args) => did::cli(args).await.unwrap(),
        DIDKitCmd::DIDCreate(args) => did::create(args).await.unwrap(),
        DIDKitCmd::DIDFromTx => did::from_tx().await.unwrap(),
        DIDKitCmd::DIDSubmitTx => did::submit_tx().await.unwrap(),
        DIDKitCmd::DIDUpdate(args) => did::update(args).await.unwrap(),
        DIDKitCmd::DIDRecover(args) => did::recover(args).await.unwrap(),
        DIDKitCmd::DIDDeactivate(args) => did::deactivate(args).await.unwrap(),
        DIDKitCmd::DIDResolve(args) => did::resolve(args).await.unwrap(),
        DIDKitCmd::DIDDereference(args) => did::dereference(args).await.unwrap(),
        DIDKitCmd::DIDAuth(args) => did::authenticate(args).await.unwrap(),
    }
    Ok(())
}
