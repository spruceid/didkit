use std::fs::File;
use std::io::{stdin, stdout, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use chrono::prelude::*;
use serde::Serialize;
use serde_json::Value;
use sshkeys::PublicKey;
use structopt::{clap::AppSettings, clap::ArgGroup, StructOpt};

use did_method_key::DIDKey;
use didkit::generate_proof;
use didkit::{
    dereference, get_verification_method, runtime, DIDMethod, DIDResolver,
    DereferencingInputMetadata, Error, LinkedDataProofOptions, Metadata, ProofFormat, ProofPurpose,
    ResolutionInputMetadata, ResolutionResult, Source, VerifiableCredential,
    VerifiablePresentation, DID_METHODS, JWK,
};
use didkit_cli::opts::ResolverOptions;

#[derive(StructOpt, Debug)]
pub enum DIDKit {
    /// Generate and output a Ed25519 keypair in JWK format
    GenerateEd25519Key,
    /// Output a did:key DID for a JWK. Deprecated in favor of key-to-did.
    #[structopt(setting = AppSettings::Hidden)]
    KeyToDIDKey {
        #[structopt(flatten)]
        key: KeyArg,
    },
    /// Output a DID for a given JWK and DID method name or pattern.
    KeyToDID {
        method_pattern: String,
        #[structopt(flatten)]
        key: KeyArg,
    },
    /// Output a verificationMethod DID URL for a JWK and DID method name/pattern
    KeyToVerificationMethod {
        method_pattern: Option<String>,
        #[structopt(flatten)]
        key: KeyArg,
    },
    /// Convert a SSH public key to a JWK
    SshPkToJwk {
        #[structopt(parse(try_from_str=PublicKey::from_string))]
        /// SSH Public Key
        ssh_pk: PublicKey,
    },

    /*
    // DID Functionality
    /// Create new DID Document.
    DIDCreate {},
    */
    /// Resolve a DID to a DID Document.
    DIDResolve {
        did: String,
        #[structopt(short = "m", long)]
        /// Return resolution result with metadata
        with_metadata: bool,
        #[structopt(short = "i", name = "name=value")]
        /// DID resolution input metadata
        input_metadata: Vec<MetadataProperty>,
        #[structopt(flatten)]
        resolver_options: ResolverOptions,
    },
    /// Dereference a DID URL to a resource.
    DIDDereference {
        did_url: String,
        #[structopt(short = "m", long)]
        /// Return resolution result with metadata
        with_metadata: bool,
        #[structopt(short = "i", name = "name=value")]
        /// DID dereferencing input metadata
        input_metadata: Vec<MetadataProperty>,
        #[structopt(flatten)]
        resolver_options: ResolverOptions,
    },
    /// Authenticate with a DID.
    DIDAuth {
        #[structopt(flatten)]
        key: KeyArg,
        #[structopt(short = "h", long)]
        holder: String,
        #[structopt(flatten)]
        proof_options: ProofOptions,
    },
    /*
    /// Update a DID Document’s authentication.
    DIDUpdateAuthentication {},
    /// Update a DID Document’s service endpoint(s).
    DIDUpdateServiceEndpoints {},
    /// Deactivate a DID.
    DIDDeactivate {},
    /// Create a Signed IETF JSON Patch to update a DID document.
    DIDPatch {},
    */
    // VC Functionality
    /// Issue Credential
    VCIssueCredential {
        #[structopt(flatten)]
        key: KeyArg,
        #[structopt(flatten)]
        proof_options: ProofOptions,
    },
    /// Verify Credential
    VCVerifyCredential {
        #[structopt(flatten)]
        proof_options: ProofOptions,
        #[structopt(flatten)]
        resolver_options: ResolverOptions,
    },
    /// Issue Presentation
    VCIssuePresentation {
        #[structopt(flatten)]
        key: KeyArg,
        #[structopt(flatten)]
        proof_options: ProofOptions,
    },
    /// Verify Presentation
    VCVerifyPresentation {
        #[structopt(flatten)]
        resolver_options: ResolverOptions,
        #[structopt(flatten)]
        proof_options: ProofOptions,
    },
    /// Convert JSON-LD to URDNA2015-canonicalized RDF N-Quads
    ToRdfURDNA2015 {
        /// Base IRI
        #[structopt(short = "b", long)]
        base: Option<String>,
        /// IRI for expandContext option
        #[structopt(short = "c", long)]
        expand_context: Option<String>,
        /// Additional values for JSON-LD @context property.
        #[structopt(short = "C", long)]
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

#[derive(StructOpt, Debug)]
#[non_exhaustive]
pub struct ProofOptions {
    // Options as in vc-http-api
    #[structopt(env, short, long)]
    pub verification_method: Option<String>,
    #[structopt(env, short, long)]
    pub proof_purpose: Option<ProofPurpose>,
    #[structopt(env, short, long)]
    pub created: Option<DateTime<Utc>>,
    #[structopt(env, short = "C", long)]
    pub challenge: Option<String>,
    #[structopt(env, short, long)]
    pub domain: Option<String>,

    // Non-standard options
    #[structopt(env, default_value, short = "f", long)]
    pub proof_format: ProofFormat,
}

#[derive(StructOpt, Debug)]
#[structopt(group = ArgGroup::with_name("key_group").multiple(true).required(true))]
pub struct KeyArg {
    #[structopt(env, short, long, parse(from_os_str), group = "key_group")]
    key_path: Option<PathBuf>,
    #[structopt(
        env,
        short,
        long,
        parse(try_from_str = serde_json::from_str),
        hide_env_values = true,
        conflicts_with = "key_path",
        group = "key_group",
        help = "WARNING: you should not use this through the CLI in a production environment, prefer its environment variable."
    )]
    jwk: Option<JWK>,
    /// Request signature using SSH Agent
    #[structopt(short = "S", long, group = "key_group")]
    ssh_agent: bool,
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
}

fn ssh_auth_sock_err() {
    eprintln!(
        r#"didkit: missing SSH_AUTH_SOCK environmental variable for SSH Agent usage.
To use DIDKit with SSH Agent, ssh-agent must be running and $SSH_AUTH_SOCK
set. For more info, see the manual for ssh-agent(1) and ssh-add(1).
"#
    );
    std::process::exit(1);
}

fn main() {
    let rt = runtime::get().unwrap();
    let opt = DIDKit::from_args();

    use std::env::VarError;
    let ssh_agent_sock = match std::env::var("SSH_AUTH_SOCK") {
        Ok(string) => Some(string),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => panic!("Unable to parse SSH_AUTH_SOCK"),
    };
    let ssh_agent_sock_opt = match ssh_agent_sock {
        Some(ref path) => Some(&path[..]),
        None => None,
    };

    match opt {
        DIDKit::GenerateEd25519Key => {
            let jwk = JWK::generate_ed25519().unwrap();
            let jwk_str = serde_json::to_string(&jwk).unwrap();
            println!("{}", jwk_str);
        }

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

        DIDKit::VCIssueCredential { key, proof_options } => {
            let credential_reader = BufReader::new(stdin());
            let mut credential: VerifiableCredential =
                serde_json::from_reader(credential_reader).unwrap();
            let proof_format = proof_options.proof_format.clone();
            let jwk_opt: Option<JWK> = key.get_jwk_opt();
            if key.ssh_agent && ssh_agent_sock.is_none() {
                ssh_auth_sock_err();
            }
            let options = LinkedDataProofOptions::from(proof_options);
            match proof_format {
                ProofFormat::JWT => {
                    if ssh_agent_sock_opt.is_some() {
                        todo!("ssh-agent for JWT not implemented");
                    }
                    let jwt = rt
                        .block_on(credential.generate_jwt(jwk_opt.as_ref(), &options))
                        .unwrap();
                    print!("{}", jwt);
                }
                ProofFormat::LDP => {
                    let proof = rt
                        .block_on(generate_proof(
                            &credential,
                            jwk_opt.as_ref(),
                            options,
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

        DIDKit::VCIssuePresentation { key, proof_options } => {
            let presentation_reader = BufReader::new(stdin());
            let mut presentation: VerifiablePresentation =
                serde_json::from_reader(presentation_reader).unwrap();
            let jwk_opt: Option<JWK> = key.get_jwk_opt();
            if key.ssh_agent && ssh_agent_sock.is_none() {
                ssh_auth_sock_err();
            }
            let proof_format = proof_options.proof_format.clone();
            let options = LinkedDataProofOptions::from(proof_options);
            match proof_format {
                ProofFormat::JWT => {
                    if ssh_agent_sock_opt.is_some() {
                        todo!("ssh-agent for JWT not implemented");
                    }
                    let jwt = rt
                        .block_on(presentation.generate_jwt(jwk_opt.as_ref(), &options))
                        .unwrap();
                    print!("{}", jwt);
                }
                ProofFormat::LDP => {
                    let proof = rt
                        .block_on(generate_proof(
                            &presentation,
                            jwk_opt.as_ref(),
                            options,
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
            use std::io::Read;
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
        } => {
            let mut presentation = VerifiablePresentation::default();
            presentation.holder = Some(ssi::vc::URI::String(holder));
            let proof_format = proof_options.proof_format.clone();
            let jwk_opt: Option<JWK> = key.get_jwk_opt();
            if key.ssh_agent && ssh_agent_sock.is_none() {
                ssh_auth_sock_err();
            }
            let options = LinkedDataProofOptions::from(proof_options);
            match proof_format {
                ProofFormat::JWT => {
                    if ssh_agent_sock_opt.is_some() {
                        todo!("ssh-agent for JWT not implemented");
                    }
                    let jwt = rt
                        .block_on(presentation.generate_jwt(jwk_opt.as_ref(), &options))
                        .unwrap();
                    print!("{}", jwt);
                }
                ProofFormat::LDP => {
                    let proof = rt
                        .block_on(generate_proof(
                            &presentation,
                            jwk_opt.as_ref(),
                            options,
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
}
