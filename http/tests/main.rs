use std::str::FromStr;

use didkit::{Document, JWK};
use didkit_cli::opts::ResolverOptions;
use didkit_http::DIDKitHTTPMakeSvc;
use didkit_http::VerifyCredentialResponse;
use didkit_http::VerifyPresentationResponse;
use ssi::did_resolve::{ResolutionResult, TYPE_DID_LD_JSON, TYPE_DID_RESOLUTION};

use hyper::body::Buf;
use hyper::header::{ACCEPT, CONTENT_TYPE};
use hyper::{Body, Client, Request, Response, Server, Uri};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};

const DID_KEY_JSON: &'static str = include_str!("../../cli/tests/ed25519-key.jwk");
const DID_KEY: &'static str = "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK";
const VERIFICATION_METHOD: &'static str = "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK#z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK";

const DID_KEY_K256: &'static str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
const DID_KEY_P256: &'static str = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";

const ISSUE_CRED_REQ: &str = r#"{
    "credential": {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "urn:uuid:5ac2b0e1-0406-49d8-8747-b9cc0d008b1d",
        "type": ["VerifiableCredential"],
        "issuer": "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK",
        "issuanceDate": "2020-11-18T20:47:16Z",
        "credentialSubject": {
            "id": "urn:uuid:d336d8e2-17a4-4601-8d89-e7ec703a751b"
        }
    },
    "options": {
        "verificationMethod": "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK#z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK",
        "proofPurpose": "assertionMethod",
        "created": "2020-11-18T20:50:10Z",
        "domain": "example.net",
        "challenge": "c16239ed-9775-4cf5-8f7a-65fc07e0d379"
    }
}"#;

fn assert_is_jsonld(resp: &Response<Body>) {
    match resp.headers()[CONTENT_TYPE].to_str().unwrap() {
        "application/json" | "application/ld+json" => {}
        content_type => panic!("Unexpected content type: {}", content_type),
    }
}

fn serve(other_keys: Option<Vec<JWK>>) -> (String, impl FnOnce() -> ()) {
    let key: JWK = serde_json::from_str(DID_KEY_JSON).unwrap();
    let mut keys = vec![key];
    if let Some(mut other_keys) = other_keys {
        keys.append(&mut other_keys);
    }
    let resolver_options = ResolverOptions::default();
    let makesvc = DIDKitHTTPMakeSvc::new(keys, resolver_options);
    let addr = ([127, 0, 0, 1], 0).into();
    let server = Server::bind(&addr).serve(makesvc);
    let url = "http://".to_string() + &server.local_addr().to_string();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let shutdown = || shutdown_tx.send(()).unwrap();
    let graceful = server.with_graceful_shutdown(async {
        shutdown_rx.await.unwrap();
    });
    tokio::task::spawn(async move {
        graceful.await.unwrap();
    });
    (url, shutdown)
}

#[tokio::test]
async fn not_found() {
    let (base, shutdown) = serve(None);
    let client = Client::builder().build_http::<Body>();

    let uri = Uri::from_str(&(base + "/nonexistent-path")).unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status(), 404);

    shutdown();
}

#[tokio::test]
async fn credential_presentation_issue_verify() {
    let (base, shutdown) = serve(None);
    let client = Client::builder().build_http::<Body>();

    // Issue credential
    let uri = Uri::from_str(&(base.to_string() + "/credentials/issue")).unwrap();
    let body = Body::from(ISSUE_CRED_REQ);
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .body(body)
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 201);
    assert_is_jsonld(&resp);
    let body_reader = hyper::body::aggregate(resp).await.unwrap().reader();
    let vc: Value = serde_json::from_reader(body_reader).unwrap();
    eprintln!("issue credential response: {:?}", vc);
    // Do a small check here and then full verification via HTTP
    assert!(!vc["proof"].is_null());

    // Verify credential
    let uri = Uri::from_str(&(base.to_string() + "/credentials/verify")).unwrap();
    let verify_cred_req = json!({
      "verifiableCredential": vc,
      "options": {
          "verificationMethod": VERIFICATION_METHOD,
          "proofPurpose": "assertionMethod",
          "domain": "example.net",
          "challenge": "c16239ed-9775-4cf5-8f7a-65fc07e0d379"
      }
    });
    let req_str = serde_json::to_string(&verify_cred_req).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::from(req_str))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_is_jsonld(&resp);
    let body_reader = hyper::body::aggregate(resp).await.unwrap().reader();
    let response: VerifyCredentialResponse = serde_json::from_reader(body_reader).unwrap();
    assert!(response.errors.is_empty());
    eprintln!("verify credential response: {:?}", response);

    // Issue presentation
    let uri = Uri::from_str(&(base.to_string() + "/credentials/prove")).unwrap();
    let challenge = "a93fdb78-411a-4a34-ab1c-be9968b92f6b";
    let issue_pres_req = json!({
      "presentation": {
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          "id": "urn:uuid:5ac2b0e1-0406-49d8-8747-b9cc0d008b1d",
          "type": ["VerifiablePresentation"],
          "holder": DID_KEY,
          "verifiableCredential": vc
      },
      "options": {
          "verificationMethod": VERIFICATION_METHOD,
          "proofPurpose": "authentication",
          "domain": "example.org",
          "challenge": challenge
      }
    });
    let req_str = serde_json::to_string(&issue_pres_req).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::from(req_str))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 201);
    assert_is_jsonld(&resp);
    let body_reader = hyper::body::aggregate(resp).await.unwrap().reader();
    let vp: Value = serde_json::from_reader(body_reader).unwrap();
    eprintln!("issue presentation response: {:?}", vp);

    // Verify presentation
    let uri = Uri::from_str(&(base.to_string() + "/presentations/verify")).unwrap();
    let verify_pres_req = json!({
      "verifiablePresentation": vp,
      "options": {
          "verificationMethod": VERIFICATION_METHOD,
          "proofPurpose": "authentication",
          "domain": "example.org",
          "challenge": challenge
      }
    });
    let req_str = serde_json::to_string(&verify_pres_req).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(&uri)
        .body(Body::from(req_str))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_is_jsonld(&resp);
    let body_reader = hyper::body::aggregate(resp).await.unwrap().reader();
    let response: VerifyPresentationResponse = serde_json::from_reader(body_reader).unwrap();
    assert!(response.errors.is_empty());
    eprintln!("verify presentation response: {:?}", response);

    // Verify invalid presentation
    let mut invalid_verify_pres_req = verify_pres_req.clone();
    invalid_verify_pres_req["verifiablePresentation"]["holder"] = Value::Null;
    let req_str = serde_json::to_string(&invalid_verify_pres_req).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(&uri)
        .body(Body::from(req_str))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_ne!(resp.status(), 200);
    assert_is_jsonld(&resp);
    let body_reader = hyper::body::aggregate(resp).await.unwrap().reader();
    let response: VerifyPresentationResponse = serde_json::from_reader(body_reader).unwrap();
    assert_ne!(response.errors.len(), 0);
    eprintln!("verify invalid presentation response: {:?}", response);

    shutdown()
}

#[tokio::test]
async fn credential_issue_verify_other_key() {
    use did_method_key::DIDKey;
    use didkit::{get_verification_method, DIDMethod, Source};
    let key = JWK::generate_ed25519().unwrap();
    let did = DIDKey.generate(&Source::Key(&key)).unwrap();
    let resolver = DIDKey.to_resolver();
    let verification_method = get_verification_method(&did, resolver).await.unwrap();
    let (base, shutdown) = serve(Some(vec![key]));
    let client = Client::builder().build_http::<Body>();
    // Issue credential
    let uri = Uri::from_str(&(base.to_string() + "/credentials/issue")).unwrap();
    let mut cred_req: Value = serde_json::from_str(ISSUE_CRED_REQ).unwrap();
    cred_req["credential"]["issuer"] = json!(did);
    cred_req["options"]["verificationMethod"] = json!(verification_method);
    let body = Body::from(serde_json::to_string(&cred_req).unwrap());
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .body(body)
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 201);
    assert_is_jsonld(&resp);
    let body_reader = hyper::body::aggregate(resp).await.unwrap().reader();
    let vc: Value = serde_json::from_reader(body_reader).unwrap();
    eprintln!("issue credential response: {:?}", vc);
    // Do a small check here and then full verification via HTTP
    assert!(!vc["proof"].is_null());
    assert_eq!(vc["issuer"], did);
    assert_eq!(vc["proof"]["verificationMethod"], verification_method);

    // Verify credential
    let uri = Uri::from_str(&(base.to_string() + "/credentials/verify")).unwrap();
    let verify_cred_req = json!({
      "verifiableCredential": vc,
      "options": {
          "verificationMethod": verification_method,
          "proofPurpose": "assertionMethod",
          "domain": "example.net",
          "challenge": "c16239ed-9775-4cf5-8f7a-65fc07e0d379"
      }
    });
    let req_str = serde_json::to_string(&verify_cred_req).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::from(req_str))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_is_jsonld(&resp);
    let body_reader = hyper::body::aggregate(resp).await.unwrap().reader();
    let response: VerifyCredentialResponse = serde_json::from_reader(body_reader).unwrap();
    assert!(response.errors.is_empty());
    eprintln!("verify credential response: {:?}", response);
    shutdown()
}

#[tokio::test]
async fn invalid_input() {
    let (base, shutdown) = serve(None);
    let client = Client::builder().build_http::<Body>();

    let uri = Uri::from_str(&(base + "/credentials/issue")).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::from("{}"))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 400);

    shutdown();
}

#[tokio::test]
async fn non_json_input() {
    let (base, shutdown) = serve(None);
    let client = Client::builder().build_http::<Body>();

    let uri = Uri::from_str(&(base + "/credentials/issue")).unwrap();
    let body = Body::from(ISSUE_CRED_REQ);
    let req = Request::builder()
        .method("POST")
        .header(CONTENT_TYPE, "text/html")
        .uri(uri)
        .body(body)
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 400);

    shutdown();
}

#[tokio::test]
async fn non_json_accept() {
    let (base, shutdown) = serve(None);
    let client = Client::builder().build_http::<Body>();

    let uri = Uri::from_str(&(base + "/credentials/issue")).unwrap();
    let body = Body::from(ISSUE_CRED_REQ);
    let req = Request::builder()
        .method("POST")
        .header(ACCEPT, "text/html")
        .uri(uri)
        .body(body)
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 406);

    shutdown();
}

#[tokio::test]
async fn resolve_dereference() {
    let (base, shutdown) = serve(None);
    let client = Client::builder().build_http::<Body>();

    // Resolve DID
    let uri_string = format!("{}/identifiers/{}", base, DID_KEY);
    let uri = Uri::from_str(&uri_string).unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body_reader = hyper::body::aggregate(resp).await.unwrap().reader();
    let doc: Document = serde_json::from_reader(body_reader).unwrap();
    assert_eq!(doc.id, DID_KEY);

    // Resolve DID with metadata
    let uri = Uri::from_str(&uri_string).unwrap();
    let req = Request::builder()
        .method("GET")
        .header(ACCEPT, TYPE_DID_RESOLUTION)
        .uri(uri)
        .body(Body::default())
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let resp_headers = resp.headers().clone();
    let body_reader = hyper::body::aggregate(resp).await.unwrap().reader();
    let result: ResolutionResult = serde_json::from_reader(body_reader).unwrap();
    eprintln!("{:?}", result);
    let res_meta = result.did_resolution_metadata.unwrap();
    let http_content_type = resp_headers
        .get(hyper::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(res_meta.error, None);
    assert_eq!(result.did_document.unwrap().id, DID_KEY);
    assert_eq!(res_meta.content_type.unwrap(), TYPE_DID_LD_JSON);
    assert_eq!(http_content_type, TYPE_DID_RESOLUTION);

    // Resolve more DIDs
    let uri = Uri::from_str(&format!("{}/identifiers/{}", base, DID_KEY_K256)).unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status(), 200);
    let uri = Uri::from_str(&format!("{}/identifiers/{}", base, DID_KEY_P256)).unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Dereference DID URL
    let uri_string = format!(
        "{}/identifiers/{}",
        base,
        utf8_percent_encode(VERIFICATION_METHOD, NON_ALPHANUMERIC)
    );
    eprintln!("uri {}", uri_string);
    let uri = Uri::from_str(&uri_string).unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body_reader = hyper::body::aggregate(resp).await.unwrap().reader();
    let vm: Value = serde_json::from_reader(body_reader).unwrap();
    eprintln!("vm {:?}", vm);

    shutdown();
}
