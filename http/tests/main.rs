use std::str::FromStr;

use didkit::JWK;
use didkit_http::DIDKitHTTPMakeSvc;
use didkit_http::VerifyCredentialResponse;
use didkit_http::VerifyPresentationResponse;

use bytes::buf::BufExt;
use hyper::header::{ACCEPT, CONTENT_TYPE};
use hyper::{Body, Client, Request, Response, Server, Uri};
use serde_json::{json, Value};

const DID_KEY_JSON: &'static str = include_str!("../../cli/tests/ed25519-key.jwk");
const DID_KEY: &'static str = "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK";

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
        "verificationMethod": "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK",
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

fn serve() -> (String, impl FnOnce() -> ()) {
    let key: JWK = serde_json::from_str(DID_KEY_JSON).unwrap();
    let makesvc = DIDKitHTTPMakeSvc::new(Some(key));
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
    let (base, shutdown) = serve();
    let client = Client::builder().build_http::<Body>();

    let uri = Uri::from_str(&(base + "/nonexistent-path")).unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status(), 404);

    shutdown();
}

#[tokio::test]
async fn credential_presentation_issue_verify() {
    let (base, shutdown) = serve();
    let client = Client::builder().build_http::<Body>();

    // Issue credential
    let uri = Uri::from_str(&(base.to_string() + "/issue/credentials")).unwrap();
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
    let uri = Uri::from_str(&(base.to_string() + "/verify/credentials")).unwrap();
    let verify_cred_req = json!({
      "verifiableCredential": vc,
      "options": {
          "verificationMethod": DID_KEY,
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
    let uri = Uri::from_str(&(base.to_string() + "/prove/presentations")).unwrap();
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
          "verificationMethod": DID_KEY,
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
    let uri = Uri::from_str(&(base.to_string() + "/verify/presentations")).unwrap();
    let verify_pres_req = json!({
      "verifiablePresentation": vp,
      "options": {
          "verificationMethod": DID_KEY,
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
async fn invalid_input() {
    let (base, shutdown) = serve();
    let client = Client::builder().build_http::<Body>();

    let uri = Uri::from_str(&(base + "/issue/credentials")).unwrap();
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
    let (base, shutdown) = serve();
    let client = Client::builder().build_http::<Body>();

    let uri = Uri::from_str(&(base + "/issue/credentials")).unwrap();
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
    let (base, shutdown) = serve();
    let client = Client::builder().build_http::<Body>();

    let uri = Uri::from_str(&(base + "/issue/credentials")).unwrap();
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
