const DIDKit = require('../native');

const version = DIDKit.getVersion();
console.log(`Using DIDKit v${version}\n`);

const key = DIDKit.generateEd25519Key();
console.log(`Key: ${JSON.stringify(key, null, 2)}\n`);

const did = DIDKit.keyToDID(key);
console.log(`Key DID: ${did}\n`);

const verificationMethod = DIDKit.keyToVerificationMethod(key);
console.log(`Key Verification Method: ${verificationMethod}\n`);

const vc = DIDKit.issueCredential({
  "@context": "https://www.w3.org/2018/credentials/v1",
  "id": "http://example.org/credentials/3731",
  "type": ["VerifiableCredential"],
  "issuer": did,
  "issuanceDate": "2020-08-19T21:41:50Z",
  "credentialSubject": {
    "id": "did:example:d23dd687a7dc6787646f2eb98d0"
  }
}, {
  "proofPurpose": "assertionMethod",
  "verificationMethod": verificationMethod
}, key);
console.log(`Verifiable Credential: ${JSON.stringify(vc, null, 2)}\n`);

const vcResult = DIDKit.verifyCredential(vc, {
  "proofPurpose": "assertionMethod"
});
console.log(`Verification Result: ${JSON.stringify(vcResult, null, 2)}\n`);

const vp = DIDKit.issuePresentation({
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "id": "http://example.org/presentations/3731",
  "type": ["VerifiablePresentation"],
  "holder": did,
  "verifiableCredential": {
    "@context": "https://www.w3.org/2018/credentials/v1",
    "id": "http://example.org/credentials/3731",
    "type": ["VerifiableCredential"],
    "issuer": "did:example:30e07a529f32d234f6181736bd3",
    "issuanceDate": "2020-08-19T21:41:50Z",
    "credentialSubject": {
      "id": "did:example:d23dd687a7dc6787646f2eb98d0"
    }
  }
}, {
  "proofPurpose": "authentication",
  "verificationMethod": verificationMethod
}, key);
console.log(`Verifiable Presentation: ${JSON.stringify(vp, null, 2)}\n`);

const vpResult = DIDKit.verifyPresentation(vp, {
  "proofPurpose": "authentication"
});
console.log(`Verification Result: ${JSON.stringify(vpResult, null, 2)}\n`);
