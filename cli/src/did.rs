use std::{
    convert::TryFrom,
    io::{stdin, stdout, BufReader, BufWriter, Write},
    path::PathBuf,
};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use didkit::{
    generate_proof,
    ssi::{
        did::{DIDMethodTransaction, Service, ServiceEndpoint, VerificationMethodMap},
        vc::OneOrMany,
    },
    ContextLoader, DIDCreate, DIDDeactivate, DIDDocumentOperation, DIDMethod, DIDRecover,
    DIDResolver, DIDUpdate, DereferencingInputMetadata, LinkedDataProofOptions, ProofFormat,
    ResolutionInputMetadata, ResolutionResult, VerifiablePresentation, DID_METHODS, JWK, URI,
};
use serde_json::json;

use crate::{
    get_ssh_agent_sock, metadata_properties_to_value, opts::ResolverOptions,
    parse_service_endpoint, read_jwk_file_opt, IdAndDid, KeyArg, MetadataProperty, ProofOptions,
    PublicKeyArg, PublicKeyArgEnum, PublicKeyProperty, VerificationRelationships,
};

#[derive(Subcommand)]
pub enum DidCmd {
    /// Create new DID Document.
    ///
    /// See also: https://identity.foundation/did-registration/#create
    ///           (method), jobId, options, secret, didDocument
    Create(DidCreateArgs),
    /// Get DID from DID method transaction
    ///
    /// Reads from standard input. Outputs DID on success.
    FromTx,
    /// Submit a DID method transaction
    ///
    /// Reads from standard input.
    SubmitTx,
    /// Update a DID.
    Update(DidUpdateArgs),
    /// Recover a DID.
    Recover(DidRecoverArgs),
    /// Resolve a DID to a DID Document.
    Resolve(DidResolveArgs),
    /// Dereference a DID URL to a resource.
    Dereference(DidDereferenceArgs),
    /// Authenticate with a DID.
    Authenticate(Box<DidAuthenticateArgs>),
    /// Deactivate a DID.
    Deactivate(DidDeactivateArgs),
}

#[derive(Args)]
pub struct DidCreateArgs {
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
}

#[derive(Args)]
pub struct DidUpdateArgs {
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
}

#[derive(Args)]
pub struct DidRecoverArgs {
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
}

#[derive(Args)]
pub struct DidResolveArgs {
    /// DID to resolve
    did: String,
    #[clap(short = 'm', long)]
    /// Return resolution result with metadata
    with_metadata: bool,
    #[clap(short = 'i', name = "name=value")]
    /// DID resolution input metadata
    input_metadata: Vec<MetadataProperty>,
    #[clap(flatten)]
    resolver_options: ResolverOptions,
}

#[derive(Args)]
pub struct DidDereferenceArgs {
    /// DID to dereference
    did_url: String,
    #[clap(short = 'm', long)]
    /// Return resolution result with metadata
    with_metadata: bool,
    #[clap(short = 'i', name = "name=value")]
    /// DID dereferencing input metadata
    input_metadata: Vec<MetadataProperty>,
    #[clap(flatten)]
    resolver_options: ResolverOptions,
}

#[derive(Args)]
pub struct DidAuthenticateArgs {
    #[clap(flatten)]
    key: KeyArg,
    #[clap(short = 'H', long)]
    holder: String,
    #[clap(flatten)]
    proof_options: ProofOptions,
    #[clap(flatten)]
    resolver_options: ResolverOptions,
}

#[derive(Args)]
pub struct DidDeactivateArgs {
    /// DID to deactivate
    did: String,
    /// Filename of JWK to perform the DID Deactivate operation
    #[clap(short, long)]
    key: Option<PathBuf>,
    #[clap(short = 'o', name = "name=value")]
    /// Options for DID deactivate operation
    options: Vec<MetadataProperty>,
}

#[derive(Subcommand, Debug)]
pub enum DIDUpdateCmd {
    #[clap(hide = true)]
    SetVerificationMethod(DIDUpdateSetVMArgs),
    #[clap(hide = true)]
    SetService(DIDUpdateSetServiceArgs),
    #[clap(hide = true)]
    RemoveService(IdAndDid),
    #[clap(hide = true)]
    RemoveVerificationMethod(IdAndDid),
    /// Set or add a parameter in the DID document
    #[clap(subcommand)]
    Set(DIDUpdateSetCmd),
    /// Remove a parameter in the DID document
    #[clap(subcommand)]
    Remove(DIDUpdateRemoveCmd),
}

#[derive(Subcommand, Debug)]
pub enum DIDUpdateSetCmd {
    /// Add a verification method to the DID document
    VerificationMethod(DIDUpdateSetVMArgs),
    /// Add a service to the DID document
    Service(DIDUpdateSetServiceArgs),
}

#[derive(Args, Debug)]
pub struct DIDUpdateSetVMArgs {
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
    public_key: Box<PublicKeyArg>,
}

#[derive(Args, Debug)]
pub struct DIDUpdateSetServiceArgs {
    #[clap(flatten)]
    id_and_did: IdAndDid,
    /// Service type
    #[clap(short, long)]
    r#type: Vec<String>,
    /// serviceEndpoint URI or JSON object
    #[clap(short, long, value_parser(parse_service_endpoint))]
    endpoint: Vec<ServiceEndpoint>,
}

#[derive(Subcommand, Debug)]
pub enum DIDUpdateRemoveCmd {
    /// Remove a service endpoint from the DID document
    Service(IdAndDid),
    /// Remove a verification method from the DID document
    VerificationMethod(IdAndDid),
}

pub async fn cli(cmd: DidCmd) -> Result<()> {
    match cmd {
        DidCmd::Create(a) => create(a).await?,
        DidCmd::FromTx => from_tx().await?,
        DidCmd::SubmitTx => submit_tx().await?,
        DidCmd::Update(a) => update(a).await?,
        DidCmd::Recover(a) => recover(a).await?,
        DidCmd::Resolve(a) => resolve(a).await?,
        DidCmd::Dereference(a) => dereference(a).await?,
        DidCmd::Authenticate(a) => authenticate(*a).await?,
        DidCmd::Deactivate(a) => deactivate(a).await?,
    };
    Ok(())
}

pub async fn create(args: DidCreateArgs) -> Result<()> {
    let method = DID_METHODS
        .get(&args.method)
        .ok_or(anyhow!("Unable to get DID method"))?;
    let verification_key = read_jwk_file_opt(&args.verification_key)
        .context("Read verification key for DID Create")?;
    let update_key =
        read_jwk_file_opt(&args.update_key).context("Read update key for DID Create")?;
    let recovery_key =
        read_jwk_file_opt(&args.recovery_key).context("Read recovery key for DID Create")?;
    let options =
        metadata_properties_to_value(args.options).context("Parse options for DID Create")?;
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
    Ok(())
}

pub async fn from_tx() -> Result<()> {
    let stdin_reader = BufReader::new(stdin());
    let tx: DIDMethodTransaction = serde_json::from_reader(stdin_reader).unwrap();
    let method = DID_METHODS
        .get(&tx.did_method)
        .ok_or(anyhow!("Unable to get DID method"))?;
    let did = method
        .did_from_transaction(tx)
        .context("Get DID from transaction")?;
    println!("{did}");
    Ok(())
}

pub async fn submit_tx() -> Result<()> {
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
    Ok(())
}

pub async fn update(args: DidUpdateArgs) -> Result<()> {
    let new_update_key =
        read_jwk_file_opt(&args.new_update_key).context("Read new update key for DID update")?;
    let update_key =
        read_jwk_file_opt(&args.update_key).context("Read update key for DID update")?;
    let options =
        metadata_properties_to_value(args.options).context("Parse options for DID update")?;
    let options = serde_json::from_value(options).context("Unable to convert options")?;

    let (did, method, operation) = match args.cmd {
        DIDUpdateCmd::SetVerificationMethod(args) => {
            update_set(DIDUpdateSetCmd::VerificationMethod(args)).await?
        }
        DIDUpdateCmd::RemoveVerificationMethod(id_and_did) => {
            update_remove(DIDUpdateRemoveCmd::VerificationMethod(id_and_did)).await?
        }
        DIDUpdateCmd::SetService(args) => update_set(DIDUpdateSetCmd::Service(args)).await?,
        DIDUpdateCmd::RemoveService(id_and_did) => {
            update_remove(DIDUpdateRemoveCmd::VerificationMethod(id_and_did)).await?
        }
        DIDUpdateCmd::Set(args) => update_set(args).await?,
        DIDUpdateCmd::Remove(args) => update_remove(args).await?,
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
    Ok(())
}

pub async fn update_set<'a>(
    cmd: DIDUpdateSetCmd,
) -> Result<(String, &'a dyn DIDMethod, DIDDocumentOperation)> {
    Ok(match cmd {
        DIDUpdateSetCmd::VerificationMethod(args) => {
            let (method, did, id) = args
                .id_and_did
                .parse()
                .context("Parse id/DID for set-verification-method subcommand")?;
            let pk_enum =
                PublicKeyArgEnum::try_from(*args.public_key).context("Read public key option")?;
            let public_key =
                PublicKeyProperty::try_from(pk_enum).context("Read public key property")?;
            let purposes = args.verification_relationships.into();
            let controller = args.controller.unwrap_or_else(|| did.clone());
            let mut vmm = VerificationMethodMap {
                id: id.to_string(),
                type_: args.type_,
                controller,
                ..Default::default()
            };
            match public_key {
                PublicKeyProperty::Jwk(jwk) => vmm.public_key_jwk = Some(*jwk),
                PublicKeyProperty::Multibase(mb) => {
                    let mut ps = std::collections::BTreeMap::<String, serde_json::Value>::default();
                    ps.insert(
                        "publicKeyMultibase".to_string(),
                        serde_json::Value::String(mb),
                    );
                    vmm.property_set = Some(ps);
                }
                PublicKeyProperty::Account(account) => {
                    vmm.blockchain_account_id = Some(account);
                }
            }
            let op = DIDDocumentOperation::SetVerificationMethod { vmm, purposes };
            (did, method, op)
        }
        DIDUpdateSetCmd::Service(args) => {
            let (method, did, id) = args
                .id_and_did
                .parse()
                .context("Parse id/DID for set-verification-method subcommand")?;
            let service_endpoint = match args.endpoint.len() {
                0 => None,
                1 => args.endpoint.into_iter().next().map(OneOrMany::One),
                _ => Some(OneOrMany::Many(args.endpoint)),
            };
            let type_ = match args.r#type.len() {
                1 => args
                    .r#type
                    .into_iter()
                    .next()
                    .map(OneOrMany::One)
                    .ok_or(anyhow!("Missing service type"))?,

                _ => OneOrMany::Many(args.r#type),
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
    })
}
pub async fn update_remove<'a>(
    cmd: DIDUpdateRemoveCmd,
) -> Result<(String, &'a dyn DIDMethod, DIDDocumentOperation)> {
    Ok(match cmd {
        DIDUpdateRemoveCmd::Service(id_and_did) => {
            let (method, did, id) = id_and_did
                .parse()
                .context("Parse id/DID for set-verification-method subcommand")?;
            let op = DIDDocumentOperation::RemoveService(id);
            (did, method, op)
        }
        DIDUpdateRemoveCmd::VerificationMethod(id_and_did) => {
            let (method, did, id) = id_and_did
                .parse()
                .context("Unable to parse id/DID for remove-verification-method subcommand")?;
            let op = DIDDocumentOperation::RemoveVerificationMethod(id);
            (did, method, op)
        }
    })
}

pub async fn recover(args: DidRecoverArgs) -> Result<()> {
    let method = DID_METHODS
        .get_method(&args.did)
        .map_err(|e| anyhow!("Unable to get DID method: {}", e))?;
    let new_verification_key = read_jwk_file_opt(&args.new_verification_key)
        .context("Read new signing key for DID recovery")?;
    let new_update_key =
        read_jwk_file_opt(&args.new_update_key).context("Read new update key for DID recovery")?;
    let new_recovery_key = read_jwk_file_opt(&args.new_recovery_key)
        .context("Read new recovery key for DID recovery")?;
    let recovery_key =
        read_jwk_file_opt(&args.recovery_key).context("Read recovery key for DID recovery")?;
    let options =
        metadata_properties_to_value(args.options).context("Parse options for DID recovery")?;
    let options = serde_json::from_value(options).context("Unable to convert options")?;

    let tx = method
        .recover(DIDRecover {
            did: args.did.clone(),
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
    Ok(())
}

pub async fn resolve(args: DidResolveArgs) -> Result<()> {
    let resolver = args.resolver_options.to_resolver();
    let res_input_meta_value = metadata_properties_to_value(args.input_metadata).unwrap();
    let res_input_meta: ResolutionInputMetadata =
        serde_json::from_value(res_input_meta_value).unwrap();
    if args.with_metadata {
        let (res_meta, doc_opt, doc_meta_opt) = resolver.resolve(&args.did, &res_input_meta).await;
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
        let (res_meta, doc_data, _doc_meta_opt) = resolver
            .resolve_representation(&args.did, &res_input_meta)
            .await;
        if let Some(err) = res_meta.error {
            eprintln!("{err}");
            std::process::exit(2);
        }
        stdout().write_all(&doc_data).unwrap();
    }
    Ok(())
}

pub async fn dereference(args: DidDereferenceArgs) -> Result<()> {
    let resolver = args.resolver_options.to_resolver();
    let deref_input_meta_value = metadata_properties_to_value(args.input_metadata).unwrap();
    let deref_input_meta: DereferencingInputMetadata =
        serde_json::from_value(deref_input_meta_value).unwrap();
    let stdout_writer = BufWriter::new(stdout());
    let (deref_meta, content, content_meta) =
        didkit::dereference(&resolver, &args.did_url, &deref_input_meta).await;
    if args.with_metadata {
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
    Ok(())
}

pub async fn authenticate(args: DidAuthenticateArgs) -> Result<()> {
    let resolver = args.resolver_options.to_resolver();
    let mut context_loader = ContextLoader::default();
    let mut presentation = VerifiablePresentation {
        holder: Some(URI::String(args.holder)),
        ..Default::default()
    };
    let proof_format = args.proof_options.proof_format.clone();
    let jwk_opt: Option<JWK> = args.key.get_jwk_opt();
    let ssh_agent_sock_opt = if args.key.ssh_agent {
        Some(get_ssh_agent_sock())
    } else {
        None
    };
    let options = LinkedDataProofOptions::from(args.proof_options);
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
                ssh_agent_sock_opt.as_deref(),
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
    Ok(())
}

pub async fn deactivate(args: DidDeactivateArgs) -> Result<()> {
    let method = DID_METHODS
        .get_method(&args.did)
        .map_err(|e| anyhow!("Unable to get DID method: {}", e))?;
    let key = read_jwk_file_opt(&args.key).context("Read key for DID deactivation")?;
    let options =
        metadata_properties_to_value(args.options).context("Parse options for DID deactivation")?;
    let options = serde_json::from_value(options).context("Unable to convert options")?;

    let tx = method
        .deactivate(DIDDeactivate {
            did: args.did.clone(),
            key,
            options,
        })
        .context("DID deactivation failed")?;
    let stdout_writer = BufWriter::new(stdout());
    serde_json::to_writer_pretty(stdout_writer, &tx).unwrap();
    println!();
    Ok(())
}
