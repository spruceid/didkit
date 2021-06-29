use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

static BIN: &str = env!("CARGO_BIN_EXE_didkit");

const DID_KEY_K256: &'static str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
const DID_KEY_P256: &'static str = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";

#[test]
fn generate_key() {
    Command::new(BIN)
        .arg("generate-ed25519-key")
        .output()
        .unwrap();
}

#[test]
fn didkit_cli() {
    // Get DID for key
    let did_output = Command::new(BIN)
        .args(&["key-to-did", "key", "--key-path", "tests/ed25519-key.jwk"])
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(did_output.status.success());
    let mut did = String::from_utf8(did_output.stdout).unwrap();
    did = did.trim().to_string();

    // Get verificationMethod for key
    let vm_output = Command::new(BIN)
        .args(&[
            "key-to-verification-method",
            "key",
            "-k",
            "tests/ed25519-key.jwk",
        ])
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
    let mut presentation: Value = serde_json::from_str(presentation_str).unwrap();
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

    // Resolve DID
    let resolve = Command::new(BIN)
        .args(&["did-resolve", "-m", &did])
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(resolve.status.success());
    let res_result_string = String::from_utf8(resolve.stdout).unwrap();
    eprintln!("{}", res_result_string);
    let res_result: Value = serde_json::from_str(&res_result_string).unwrap();
    assert_ne!(res_result["didDocument"], Value::Null);
    assert_ne!(res_result["didResolutionMetadata"], Value::Null);
    assert_ne!(res_result["didDocumentMetadata"], Value::Null);
    assert_eq!(res_result["didResolutionMetadata"]["error"], Value::Null);

    // Resolve more DIDs
    let resolve = Command::new(BIN)
        .args(&["did-resolve", DID_KEY_K256])
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(resolve.status.success());
    let resolve = Command::new(BIN)
        .args(&["did-resolve", DID_KEY_P256])
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(resolve.status.success());

    // Dereference a DID URL to a verification method
    let deref = Command::new(BIN)
        .args(&["did-dereference", "-m", &verification_method])
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(deref.status.success());
    let deref_result_string = String::from_utf8(deref.stdout).unwrap();
    eprintln!("{}", deref_result_string);
    let deref_result: Value = serde_json::from_str(&deref_result_string).unwrap();
    let deref_vec = deref_result
        .as_array()
        .expect("Expected array dereferencing result");
    assert_eq!(deref_vec.len(), 3);
    assert_ne!(deref_vec[0], Value::Null);
    assert_eq!(deref_vec[0]["didResolutionMetadata"]["error"], Value::Null);
    assert_ne!(deref_vec[1], Value::Null);
    assert_ne!(deref_vec[2], Value::Null);

    // Create DIDAuth verifiable presentation
    let mut issue_presentation = Command::new(BIN)
        .args(&[
            "did-auth",
            "-k",
            "tests/ed25519-key.jwk",
            "-h",
            &did.to_string(),
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

    // Verify DIDAuth presentation
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

    // Convert JSON-LD to RDF N-Quads with URDNA2015
    let mut to_rdf = Command::new(BIN)
        .args(&["to-rdf-urdna2015"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let jsonld = r#"{
      "@context": {
        "a": {
          "@id": "example:foo:a",
          "@type": "example:foo:something"
        },
        "b": "example:bar:b",
        "c": "example:cat"
      },
      "a": "aaa",
      "b": {
        "c": "AAA"
      }
    }"#;
    let rdf_expected = r#"_:c14n0 <example:bar:b> _:c14n1 .
_:c14n0 <example:foo:a> "aaa"^^<example:foo:something> .
_:c14n1 <example:cat> "AAA" .
"#;
    let to_rdf_stdin = to_rdf.stdin.as_mut().unwrap();
    to_rdf_stdin.write_all(jsonld.as_bytes()).unwrap();
    let to_rdf_output = to_rdf.wait_with_output().unwrap();
    assert!(to_rdf_output.status.success());
    let rdf = String::from_utf8(to_rdf_output.stdout).unwrap();
    assert_eq!(rdf, rdf_expected);
}

#[tokio::test]
async fn resolver_option() {
    use serde_json::json;
    use ssi::did_resolve::TYPE_DID_RESOLUTION;
    use ssi::jsonld::DID_RESOLUTION_V1_CONTEXT;
    use std::collections::HashMap;
    fn did_resolver_server(
        results: HashMap<String, (Option<String>, Value)>,
    ) -> Result<(String, impl FnOnce() -> Result<(), ()>), hyper::Error> {
        use hyper::header::CONTENT_TYPE;
        use hyper::service::{make_service_fn, service_fn};
        use hyper::{Body, Response, Server, StatusCode};
        let addr = ([127, 0, 0, 1], 0).into();
        let make_svc = make_service_fn(move |_| {
            let results = results.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let results = results.clone();
                    let uri = req.uri();
                    // skip root "/" to get requested DID or DID URL
                    let path: String = uri.path().chars().skip(1).collect();
                    let url = percent_encoding::percent_decode(path.as_bytes())
                        .decode_utf8()
                        .unwrap()
                        .to_string();
                    async move {
                        if let Some((type_opt, result)) = results.get(&url) {
                            let body = Body::from(serde_json::to_vec_pretty(&result).unwrap());
                            let mut response = Response::new(body);
                            if let Some(content_type) = type_opt {
                                response
                                    .headers_mut()
                                    .insert(CONTENT_TYPE, content_type.parse().unwrap());
                            }
                            return Ok::<_, hyper::Error>(response);
                        }

                        let body = Body::from(Vec::new());
                        let response = Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .header(CONTENT_TYPE, "application/json")
                            .body(body)
                            .unwrap();
                        return Ok::<_, hyper::Error>(response);
                    }
                }))
            }
        });
        let server = Server::try_bind(&addr)?.serve(make_svc);
        let url = "http://".to_string() + &server.local_addr().to_string() + "/";
        let (shutdown_tx, shutdown_rx) = futures::channel::oneshot::channel();
        let graceful = server.with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        });
        tokio::task::spawn(async move {
            graceful.await.ok();
        });
        let shutdown = || shutdown_tx.send(());
        Ok((url, shutdown))
    }

    let mut results = HashMap::new();
    results.insert(
        "did:example:empty".to_string(),
        (
            Some(TYPE_DID_RESOLUTION.to_string()),
            json!({
                "@context": DID_RESOLUTION_V1_CONTEXT,
                "didDocument": {
                  "@context": ["https://www.w3.org/ns/did/v1"],
                  "id": "did:example:empty"
                },
                "didDocumentMetadata": {},
                "didResolutionMetadata": {}
            }),
        ),
    );
    results.insert(
        "did:example:thing".to_string(),
        (
            Some(TYPE_DID_RESOLUTION.to_string()),
            json!({
                "@context": DID_RESOLUTION_V1_CONTEXT,
                "didDocument": {
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:example:thing",
                    "verificationMethod": [{
                        "id": "did:example:thing#key1",
                        "controller": "did:example:thing",
                        "type": "Ed25519VerificationKey2018",
                        "publicKeyJwk": {
                          "kty": "OKP",
                          "crv": "Ed25519",
                          "x": "PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I"
                        }
                    }]
                },
                "didDocumentMetadata": {},
                "didResolutionMetadata": {
                    "contentType": "application/did+ld+json"
                }
            }),
        ),
    );
    results.insert(
        "did:example:thing/path".to_string(),
        (
            Some("application/ld+json".to_string()),
            json!({
                "@id": "did:example:thing/path",
            }),
        ),
    );
    let (endpoint, shutdown) = did_resolver_server(results).unwrap();

    // Resolve DID with -r option for fallback HTTP resolver
    use tokio::process::Command;
    let resolve = Command::new(BIN)
        .args(&["did-resolve", "-r", &endpoint, "did:example:empty"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .await
        .unwrap();
    let resolve_result_string = String::from_utf8(resolve.stdout).unwrap();
    eprintln!("resolve: {}", resolve_result_string);
    assert!(resolve.status.success());

    // Resolve DID URL with -r option for fallback HTTP resolver
    // Dereference secondary resource client-side
    let deref = Command::new(BIN)
        .args(&["did-dereference", "-r", &endpoint, "did:example:thing#key1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .await
        .unwrap();
    let deref_result_string = String::from_utf8(deref.stdout).unwrap();
    eprintln!("dereference: {}", deref_result_string);
    assert!(deref.status.success());
    let deref_result: Value = serde_json::from_str(&deref_result_string).unwrap();
    assert_eq!(deref_result["id"], json!("did:example:thing#key1"));

    // Resolve DID URL with -r option for fallback HTTP resolver
    // DID URL with path
    let deref = Command::new(BIN)
        .args(&["did-dereference", "-r", &endpoint, "did:example:thing/path"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .await
        .unwrap();
    let deref_result_string = String::from_utf8(deref.stdout).unwrap();
    eprintln!("dereference with path: {}", deref_result_string);
    assert!(deref.status.success());
    let deref_result: Value = serde_json::from_str(&deref_result_string).unwrap();
    assert_eq!(deref_result, json!({"@id": "did:example:thing/path"}));

    shutdown().ok();
}
