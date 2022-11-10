use std::io::{stdout, BufWriter};

use anyhow::Result;
use clap::{Args, Subcommand};
use didkit::{get_verification_method, ssi::ssh, Error, Source, DID_METHODS, JWK};
use sshkeys::PublicKey;

#[derive(Subcommand)]
pub enum KeyCmd {
    /// Generate and output a keypair in JWK format
    #[clap(subcommand)]
    Generate(KeyGenerateCmd),
    /// Transform a key (e.g. JWK) into other formats (e.g. DIDs)
    #[clap(subcommand)]
    To(Box<KeyToCmd>),
    /// Get a key (e.g. JWK) from other formats (e.g. SSH public key)
    #[clap(subcommand)]
    From(Box<KeyFromCmd>),
}

#[derive(Subcommand)]
pub enum KeyToCmd {
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
    Did(KeyToDIDArgs),
    /// Output a verificationMethod DID URL for a JWK and DID method name/pattern
    VerificationMethod(KeyToVMArgs),
}

#[derive(Subcommand)]
pub enum KeyFromCmd {
    /// Convert a SSH public key to a JWK
    Ssh(KeyFromSSHArgs),
}

#[derive(Subcommand)]
pub enum KeyGenerateCmd {
    /// Generate and output a Ed25519 keypair in JWK format
    Ed25519,
    /// Generate and output a K-256 keypair in JWK format
    Secp256k1,
    /// Generate and output a P-256 keypair in JWK format
    Secp256r1,
    /// Generate and output a P-384 keypair in JWK format
    Secp384r1,
}

#[derive(Args)]
pub struct KeyToDIDArgs {
    /// DID method name or pattern. e.g. `key`, `tz`, or `pkh:tz`
    #[clap(default_value = "key")]
    pub method_pattern: String,
    #[clap(flatten)]
    pub key: crate::KeyArg,
}

#[derive(Args)]
pub struct KeyToVMArgs {
    /// DID method id or pattern. e.g. `key`, `tz`, or `pkh:tz`
    pub method_pattern: Option<String>,
    #[clap(flatten)]
    pub key: crate::KeyArg,
}

#[derive(Args)]
pub struct KeyFromSSHArgs {
    /// SSH Public Key
    ssh_pk: String,
}

pub async fn cli(cmd: KeyCmd) -> Result<()> {
    match cmd {
        KeyCmd::Generate(cmd_generate) => generate(cmd_generate).await?,
        KeyCmd::To(cmd_to) => to(*cmd_to).await?,
        KeyCmd::From(cmd_from) => from(*cmd_from).await?,
    };
    Ok(())
}

pub async fn to(cmd: KeyToCmd) -> Result<()> {
    match cmd {
        KeyToCmd::Did(cmd_did) => to_did(cmd_did).await?,
        KeyToCmd::VerificationMethod(cmd_vm) => to_vm(cmd_vm).await?,
    };
    Ok(())
}

pub async fn from(cmd: KeyFromCmd) -> Result<()> {
    match cmd {
        KeyFromCmd::Ssh(cmd_ssh) => from_ssh(cmd_ssh).await?,
    };
    Ok(())
}

pub async fn generate(cmd: KeyGenerateCmd) -> Result<()> {
    let jwk = match cmd {
        KeyGenerateCmd::Ed25519 => JWK::generate_ed25519().unwrap(),
        KeyGenerateCmd::Secp256k1 => JWK::generate_secp256k1().unwrap(),
        KeyGenerateCmd::Secp256r1 => JWK::generate_p256().unwrap(),
        KeyGenerateCmd::Secp384r1 => JWK::generate_p384().unwrap(),
    };
    let jwk_str = serde_json::to_string(&jwk).unwrap();
    println!("{jwk_str}");
    Ok(())
}

pub async fn to_did(args: KeyToDIDArgs) -> Result<()> {
    let jwk = args.key.get_jwk();
    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(&jwk, &args.method_pattern))
        .ok_or(Error::UnableToGenerateDID)
        .unwrap();
    println!("{did}");
    Ok(())
}
pub async fn to_vm(args: KeyToVMArgs) -> Result<()> {
    let method_pattern = match args.method_pattern {
        Some(pattern) => pattern,
        None => {
            eprintln!(
                "didkit: key-to-verification-method should be used with method pattern option"
            );
            "key".to_string()
        }
    };
    let jwk = args.key.get_jwk();
    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(&jwk, &method_pattern))
        .ok_or(Error::UnableToGenerateDID)
        .unwrap();
    let did_resolver = DID_METHODS.to_resolver();
    let vm = get_verification_method(&did, did_resolver)
        .await
        .ok_or(Error::UnableToGetVerificationMethod)
        .unwrap();
    println!("{vm}");
    Ok(())
}

pub async fn from_ssh(args: KeyFromSSHArgs) -> Result<()> {
    // Deserializing here because PublicKey doesn't derive Clone
    let ssh_pk = PublicKey::from_string(&args.ssh_pk).unwrap();
    let jwk = ssh::ssh_pkk_to_jwk(&ssh_pk.kind).unwrap();
    let stdout_writer = BufWriter::new(stdout());
    serde_json::to_writer_pretty(stdout_writer, &jwk).unwrap();
    Ok(())
}
