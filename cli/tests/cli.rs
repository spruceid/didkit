use std::fs::File;
use std::io::{BufReader, Write};
use std::process::{Command, Stdio};

static BIN: &str = env!("CARGO_BIN_EXE_didkit");

#[test]
fn generate_key() {
    Command::new(BIN)
        .arg("generate-ed25519-key")
        .output()
        .unwrap();
}

#[test]
fn issue_verify_credential_presentation() {
    // Get DID for key
    let did_output = Command::new(BIN)
        .args(&["key-to-did-key", "-k", "tests/ed25519-key.jwk"])
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(did_output.status.success());
    let did = String::from_utf8(did_output.stdout).unwrap();

    // Issue credential
    let credential_file = File::open("tests/credential-unsigned.jsonld").unwrap();
    let issue_credential = Command::new(BIN)
        .args(&[
            "vc-issue-credential",
            "-k",
            "tests/ed25519-key.jwk",
            "-v",
            &did.trim(),
            "-p",
            "assertionMethod",
        ])
        .stdin(Stdio::from(credential_file))
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(issue_credential.status.success());
    let vc = issue_credential.stdout;

    // Verify credential
    let mut verify_credential = Command::new(BIN)
        .args(&["vc-verify-credential", "-p", "assertionMethod"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let verify_stdin = verify_credential.stdin.as_mut().unwrap();
    verify_stdin.write_all(&vc).unwrap();
    let verify_output = verify_credential.wait_with_output().unwrap();
    assert!(verify_output.status.success());

    // Issue presentation with credential
    let presentation_file = File::open("tests/presentation-unsigned.jsonld").unwrap();
    let mut presentation: serde_json::Value =
        serde_json::from_reader(BufReader::new(presentation_file)).unwrap();
    let vc_value = serde_json::from_slice(&vc).unwrap();
    presentation["verifiableCredential"] = vc_value;
    let mut issue_presentation = Command::new(BIN)
        .args(&[
            "vc-issue-presentation",
            "-k",
            "tests/ed25519-key.jwk",
            "-v",
            &did.trim(),
            "-p",
            "authentication",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let issue_stdin = issue_presentation.stdin.as_mut().unwrap();
    serde_json::to_writer(issue_stdin, &presentation).unwrap();
    let issue_output = issue_presentation.wait_with_output().unwrap();
    assert!(issue_output.status.success());
    let vp = issue_output.stdout;
    // io::stdout().write_all(&vp).unwrap();

    // Verify presentation
    let mut verify_presentation = Command::new(BIN)
        .args(&["vc-verify-presentation", "-p", "authentication"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let verify_stdin = verify_presentation.stdin.as_mut().unwrap();
    verify_stdin.write_all(&vp).unwrap();
    let verify_output = verify_presentation.wait_with_output().unwrap();
    assert!(verify_output.status.success());
}
