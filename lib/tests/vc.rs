use didkit::VerifiableCredential;

#[test]
fn verify_credential() {
    let vc_str = r###"{
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "issuer": "did:example:30e07a529f32d234f6181736bd3",
        "issuanceDate": "2020-08-19T21:41:50Z",
        "credentialSubject": {
            "id": "did:example:d23dd687a7dc6787646f2eb98d0"
        }
    }"###;
    let _cred = VerifiableCredential::from_json_unsigned(vc_str).unwrap();
}
