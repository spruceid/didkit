use crate::LinkedDataProofOptions;
use sshkeys::PublicKey;
use ssi::jwk::{Algorithm, JWK};
use ssi::ldp::LinkedDataProofs;
use std::convert::TryFrom;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

/// Requests from client to agent
/// <https://tools.ietf.org/html/draft-miller-ssh-agent-04#section-5.1>
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;

/// Replies from agent to client
const SSH_AGENT_FAILURE: u8 = 5;
// const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Signature flags
/// <https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-5.3>
const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

#[derive(Error, Debug)]
pub enum SignError {
    #[error("Read: {0}")]
    Read(#[from] ReadError),
    #[error("Send: {0}")]
    Send(#[from] SendError),
    #[error("List keys: {0}")]
    ListKeys(#[from] ListKeysError),
    #[error("No keys")]
    NoKeys,
    #[error("Too many keys")]
    TooManyKeys,
    #[error("Signature request failed")]
    SignatureRequestFailed,
    #[error("Signature algorithm '{0}' not valid for JWS algorithm '{1:?}'")]
    SignatureAlgorithmMismatch(String, Algorithm),
    #[error("Unexpected reply to signature request: {0}")]
    UnexpectedAnswer(u8),
    #[error("Length conversion: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error("Try from slice: {0}")]
    TryFromSlice(#[from] core::array::TryFromSliceError),
    #[error("Signature Utf8: {0}")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("SSH parsing: {0}")]
    SshParsing(#[from] sshkeys::Error),
    #[error("Unsupported signing input format")]
    UnsupportedSigningInputFormat,
    #[error("Unsupported JWS algorithm: {0:?}")]
    UnsupportedAlgorithm(Algorithm),
    #[error("Unable to get JWS algorithm")]
    MissingAlgorithm,
    #[error("Unable to convert SSH Key To JWK: {0}")]
    SSHKeyToJWKError(#[from] ssi::ssh::SSHKeyToJWKError),
    #[error("Unable to calculate JWK thumbprint: {0}")]
    JWKThumbprint(String),
    #[error("Unable to prepare proof: {0}")]
    Prep(#[from] ssi::error::Error),
    #[error("RSA key must be at least 2048 bits")]
    RSAKeyTooSmall,
}

#[derive(Error, Debug)]
pub enum SendError {
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Length mismatch")]
    LengthMismatch,
    #[error("Length conversion: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
}

#[derive(Error, Debug)]
pub enum ReadError {
    #[error("IO: {0}")]
    IO(#[from] std::io::Error),
    #[error("Length conversion: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
}

#[derive(Error, Debug)]
pub enum ListKeysError {
    #[error("Send: {0}")]
    Send(#[from] SendError),
    #[error("Read: {0}")]
    Read(#[from] ReadError),
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Unexpected reply to key list request: {0}")]
    UnexpectedAnswer(u8),
    #[error("Length conversion: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error("Try from slice: {0}")]
    TryFromSlice(#[from] core::array::TryFromSliceError),
    #[error("Comment Utf8: {0}")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("SSH parsing: {0}")]
    SshParsing(#[from] sshkeys::Error),
}

#[derive(Debug)]
struct Message {
    pub type_: u8,
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone)]
struct SSHKey {
    pub comment: String,
    pub key_blob: Vec<u8>,
    pub key_type: String,
}

async fn read_msg(ssh_agent_sock: &mut tokio::net::UnixStream) -> Result<Message, ReadError> {
    use bytes::BytesMut;
    let len = ssh_agent_sock.read_u32().await?;
    let msg_type = ssh_agent_sock.read_u8().await?;
    let len = usize::try_from(len)? - 1;
    let mut contents = BytesMut::with_capacity(len);
    let mut remaining = len;
    while remaining > 0 {
        let read = ssh_agent_sock.read_buf(&mut contents).await?;
        remaining -= read;
    }
    Ok(Message {
        type_: msg_type,
        contents: contents.to_vec(),
    })
}

async fn send_msg(
    ssh_agent_sock: &mut tokio::net::UnixStream,
    msg: Message,
) -> Result<(), SendError> {
    let len = u32::try_from(msg.contents.len())? + 1;
    ssh_agent_sock.write_u32(len).await?;
    ssh_agent_sock.write_u8(msg.type_).await?;
    ssh_agent_sock.write_all(&msg.contents).await?;
    Ok(())
}

async fn list_keys(
    ssh_agent_sock: &mut tokio::net::UnixStream,
) -> Result<Vec<PublicKey>, ListKeysError> {
    send_msg(
        ssh_agent_sock,
        Message {
            type_: SSH_AGENTC_REQUEST_IDENTITIES,
            contents: Vec::new(),
        },
    )
    .await?;
    let reply = read_msg(ssh_agent_sock).await?;
    if reply.type_ != SSH_AGENT_IDENTITIES_ANSWER {
        return Err(ListKeysError::UnexpectedAnswer(reply.type_));
    }
    let mut reader = sshkeys::Reader::new(&reply.contents);
    let nkeys = usize::try_from(reader.read_u32()?)?;
    let mut keys = Vec::with_capacity(nkeys);
    let mut remaining = nkeys;
    while remaining > 0 {
        let key_blob = reader.read_bytes()?;
        let comment = reader.read_string()?;
        let mut key = PublicKey::from_bytes(&key_blob)?;
        key.comment = Some(comment);
        keys.push(key);
        remaining -= 1;
    }

    Ok(keys)
}

/// Return the first SSH public key that matches a given JWK
fn select_key(keys: Vec<PublicKey>, jwk: Option<&JWK>) -> Result<(JWK, PublicKey), SignError> {
    let jwk = match jwk {
        Some(jwk) => jwk,
        None => {
            if keys.len() > 1 {
                return Err(SignError::TooManyKeys);
            }
            let pk = keys.into_iter().next().ok_or(SignError::NoKeys)?;
            let jwk = ssi::ssh::ssh_pkk_to_jwk(&pk.kind)?;
            return Ok((jwk, pk));
        }
    };
    let thumbprint = jwk
        .thumbprint()
        .map_err(|e| SignError::JWKThumbprint(e.to_string()))?;
    for pk in keys {
        let sshkey_jwk = ssi::ssh::ssh_pkk_to_jwk(&pk.kind)?;
        let sshkey_thumbprint = sshkey_jwk
            .thumbprint()
            .map_err(|e| SignError::JWKThumbprint(e.to_string()))?;
        if sshkey_thumbprint == thumbprint {
            return Ok((sshkey_jwk, pk));
        }
    }
    Err(SignError::NoKeys)
}

async fn sign(
    ssh_agent_sock: &mut tokio::net::UnixStream,
    pk: &sshkeys::PublicKey,
    signing_input: &[u8],
    alg: Algorithm,
) -> Result<Vec<u8>, SignError> {
    if pk.key_type.kind == sshkeys::KeyTypeKind::Rsa && pk.bits() < 2048 {
        // RSA key size must be 2048 bits or larger.
        // https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
        return Err(SignError::RSAKeyTooSmall);
    }
    let mut writer = sshkeys::Writer::new();
    writer.write_bytes(&pk.encode());
    writer.write_bytes(signing_input);
    // writer doesn't have write_u32
    let mut flags: u32 = 0;
    // Without flag, signature type for RSA is "ssh-rsa" which uses SHA-1, and is deprecated:
    // https://datatracker.ietf.org/doc/html/rfc4253#page-15
    // https://www.openssh.com/txt/release-8.2
    match alg {
        Algorithm::RS256 => {
            flags |= SSH_AGENT_RSA_SHA2_256;
        }
        Algorithm::RS512 => {
            flags |= SSH_AGENT_RSA_SHA2_512;
        }
        Algorithm::EdDSA => {}
        Algorithm::ES256 => {}
        // Algorithm::ES384 => {}
        // Algorithm::ES512 => {}
        alg => {
            return Err(SignError::UnsupportedAlgorithm(alg));
        }
    }
    let flag_bytes = flags.to_be_bytes().to_vec();
    let sign_req_bytes = [
        // string  key blob
        // string  data
        writer.into_bytes(),
        // uint32  flags
        flag_bytes,
    ]
    .concat();
    send_msg(
        ssh_agent_sock,
        Message {
            type_: SSH_AGENTC_SIGN_REQUEST,
            contents: sign_req_bytes,
        },
    )
    .await?;
    let reply = read_msg(ssh_agent_sock).await?;
    match reply.type_ {
        SSH_AGENT_FAILURE => {
            return Err(SignError::SignatureRequestFailed);
        }
        SSH_AGENT_SIGN_RESPONSE => (),
        type_ => {
            return Err(SignError::UnexpectedAnswer(type_));
        }
    };
    let mut reader = sshkeys::Reader::new(&reply.contents);
    let bytes = reader.read_bytes()?;
    let mut reader = sshkeys::Reader::new(&bytes);
    let sig_type = reader.read_string()?;
    // Verify that sig type corresponds with verification method / public key type
    // https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
    // https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-19
    match (&sig_type[..], alg) {
        // https://datatracker.ietf.org/doc/html/rfc8332#section-3
        ("rsa-sha2-256", Algorithm::RS256) => {}
        ("rsa-sha2-512", Algorithm::RS512) => {}
        // https://datatracker.ietf.org/doc/html/rfc8709#section-6
        ("ssh-ed25519", Algorithm::EdDSA) => {}
        // https://datatracker.ietf.org/doc/html/rfc5656#section-6.2
        ("ecdsa-sha2-nistp256", Algorithm::ES256) => {}
        // ("ecdsa-sha2-nistp384", Algorithm::ES384) => {}
        // ("ecdsa-sha2-nistp521", Algorithm::ES512) => {}
        _ => {
            return Err(SignError::SignatureAlgorithmMismatch(sig_type, alg));
        }
    }
    let mut sig = reader.read_bytes()?;
    if sig_type.starts_with("ecdsa-sha2-") {
        let mut reader = sshkeys::Reader::new(&sig);
        // https://datatracker.ietf.org/doc/html/rfc4251#page-9
        // https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2
        let r = reader.read_mpint()?;
        let s = reader.read_mpint()?;
        // https://docs.rs/ecdsa/0.11.0/ecdsa/struct.Signature.html
        sig = [r, s].concat();
    }
    Ok(sig)
}

/// Generate Linked Data Proof over Document using signature from SSH Agent.
pub async fn generate_proof(
    ssh_agent_sock: &mut tokio::net::UnixStream,
    document: &(dyn ssi::ldp::LinkedDataDocument + Sync),
    options: LinkedDataProofOptions,
    jwk_opt: Option<&JWK>,
) -> Result<ssi::vc::Proof, SignError> {
    let keys = list_keys(ssh_agent_sock).await?;
    let (jwk, pk) = select_key(keys, jwk_opt)?;
    let prep = LinkedDataProofs::prepare(document, &options, &jwk).await?;
    let signing_input_bytes = match prep.signing_input {
        ssi::ldp::SigningInput::Bytes(ref bytes) => bytes.0.to_vec(),
        _ => Err(SignError::UnsupportedSigningInputFormat)?,
    };
    let alg = match prep.jws_header {
        Some(ref header) => header.algorithm,
        None => jwk.get_algorithm().ok_or(SignError::MissingAlgorithm)?,
    };
    let sig = sign(ssh_agent_sock, &pk, &signing_input_bytes, alg).await?;
    let sig_b64 = base64::encode_config(sig, base64::URL_SAFE_NO_PAD);
    let proof = prep.complete(&sig_b64).await?;
    Ok(proof)
}
