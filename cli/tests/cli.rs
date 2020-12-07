use std::io::Write;
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
        .args(&["key-to-did-key", "--key-path", "tests/ed25519-key.jwk"])
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(did_output.status.success());
    let mut did = String::from_utf8(did_output.stdout).unwrap();
    did = did.trim().to_string();

    // Get verificationMethod for key
    let vm_output = Command::new(BIN)
        .args(&["key-to-verification-method", "-k", "tests/ed25519-key.jwk"])
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(vm_output.status.success());
    let mut verification_method = String::from_utf8(vm_output.stdout).unwrap();
    verification_method = verification_method.trim().to_string();

    // Issue credential
    let vc = format!(
        r#"{{
       "@context": "https://www.w3.org/2018/credentials/v1",
       "id": "http://example.org/credentials/3731",
       "type": ["VerifiableCredential"],
       "issuer": "{}",
       "issuanceDate": "2020-08-19T21:41:50Z",
       "credentialSubject": {{
           "id": "did:example:d23dd687a7dc6787646f2eb98d0"
       }}
    }}"#,
        did
    );
    let mut issue_credential = Command::new(BIN)
        .args(&[
            "vc-issue-credential",
            "-k",
            "tests/ed25519-key.jwk",
            "-v",
            &verification_method.trim(),
            "-p",
            "assertionMethod",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let issue_stdin = issue_credential.stdin.as_mut().unwrap();
    issue_stdin.write_all(vc.as_bytes()).unwrap();
    let issue_output = issue_credential.wait_with_output().unwrap();
    assert!(issue_output.status.success());
    let vc = issue_output.stdout;

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
    let presentation_str = r#"{
       "@context": ["https://www.w3.org/2018/credentials/v1"],
       "id": "http://example.org/presentations/3731",
       "type": ["VerifiablePresentation"]
    }"#;
    let mut presentation: serde_json::Value = serde_json::from_str(presentation_str).unwrap();
    let vc_value = serde_json::from_slice(&vc).unwrap();
    presentation["holder"] = did.to_string().into();
    presentation["verifiableCredential"] = vc_value;
    let mut issue_presentation = Command::new(BIN)
        .args(&[
            "vc-issue-presentation",
            "-k",
            "tests/ed25519-key.jwk",
            "-v",
            &verification_method.trim(),
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
