import XCTest

@testable import DIDKitSwift

class DIDKitTests: XCTestCase {

  func test_version() {
    let version = DIDKit.version()
    XCTAssertFalse(version.isEmpty)
  }

  func test_generateEd25519Key() throws {
    let key = try DIDKit.generateEd25519Key()
    XCTAssertFalse(key.isEmpty)
  }

  func test_keyToDID() throws {
    let key = try DIDKit.generateEd25519Key()
    let did = try DIDKit.keyToDID(method: "key", jwk: key)
    XCTAssertFalse(did.isEmpty)
  }

  func test_keyToVerificationMethod() throws {
    let key = try DIDKit.generateEd25519Key()
    let vm = try DIDKit.keyToVerificationMethod(method: "key", jwk: key)
    XCTAssertFalse(vm.isEmpty)
  }

  func test_issueAndVerifyCredential() throws {
    let key = try DIDKit.generateEd25519Key()
    let did = try DIDKit.keyToDID(method: "key", jwk: key)
    let verificationMethod = try DIDKit.keyToVerificationMethod(method: "key", jwk: key)
    let options = [
      "proofPurpose": "assertionMethod",
      "verificationMethod": verificationMethod,
    ]
    let credential: [String: Any] = [
      "@context": "https://www.w3.org/2018/credentials/v1",
      "id": "http://example.org/credentials/3731",
      "type": ["VerifiableCredential"],
      "issuer": did,
      "issuanceDate": "2020-08-19T21:41:50Z",
      "credentialSubject": ["id": "did:example:d23dd687a7dc6787646f2eb98d0"],
    ]
    let vc = try DIDKit.issueCredential(
      credential: JSON.encode(credential), options: JSON.encode(options), jwk: key)
    let verifyOptions = ["proofPurpose": "assertionMethod"]
    let verifyResult =
      try JSON.decode(DIDKit.verifyCredential(credential: vc, options: JSON.encode(verifyOptions)))
      as! [String: Any]
    XCTAssertTrue((verifyResult["errors"] as! [Any]).isEmpty)
  }

  func test_issueAndVerifyPresentation() throws {
    let key = try DIDKit.generateEd25519Key()
    let did = try DIDKit.keyToDID(method: "key", jwk: key)
    let verificationMethod = try DIDKit.keyToVerificationMethod(method: "key", jwk: key)
    let options = [
      "proofPurpose": "authentication",
      "verificationMethod": verificationMethod,
    ]
    let presentation: [String: Any] = [
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "id": "http://example.org/presentations/3731",
      "type": ["VerifiablePresentation"],
      "holder": did,
      "verifiableCredential": [
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "issuer": "did:example:30e07a529f32d234f6181736bd3",
        "issuanceDate": "2020-08-19T21:41:50Z",
        "credentialSubject": ["id": "did:example:d23dd687a7dc6787646f2eb98d0"],
      ],
    ]
    let vc = try DIDKit.issuePresentation(
      presentation: JSON.encode(presentation), options: JSON.encode(options), jwk: key)
    let verifyOptions = ["proofPurpose": "authentication"]
    let verifyResult = try XCTUnwrap(
      try JSON.decode(
        DIDKit.verifyPresentation(presentation: vc, options: JSON.encode(verifyOptions)))
        as? [String: Any])
    let errors = try XCTUnwrap(verifyResult["errors"] as? [Any])
    XCTAssertTrue(errors.isEmpty)
  }

  func test_resolveDID() throws {
    let key = try DIDKit.generateEd25519Key()
    let did = try DIDKit.keyToDID(method: "key", jwk: key)
    let resolutionResult = try XCTUnwrap(
      try JSON.decode(DIDKit.resolveDID(did: did, inputMetadata: "{}")) as? [String: Any])
    let didDocument = try XCTUnwrap(resolutionResult["didDocument"] as? [String: Any])
    XCTAssertFalse(didDocument.isEmpty)
  }

  func test_dereferenceDIDURL() throws {
    let key = try DIDKit.generateEd25519Key()
    let verificationMethod = try DIDKit.keyToVerificationMethod(method: "key", jwk: key)
    let derefResult = try JSON.decode(
      DIDKit.dereferenceDIDURL(didURL: verificationMethod, inputMetadata: "{}"))
    let list = try XCTUnwrap(derefResult as? [Any])
    XCTAssertFalse(list.isEmpty)
  }

  func test_didAuth() throws {
    let key = try DIDKit.generateEd25519Key()
    let did = try DIDKit.keyToDID(method: "key", jwk: key)
    let verificationMethod = try DIDKit.keyToVerificationMethod(method: "key", jwk: key)
    let challenge = UUID().uuidString
    let proofOptions = [
      "proofPurpose": "assertionMethod",
      "verificationMethod": verificationMethod,
      "challenge": challenge,
    ]
    let vp = try DIDKit.didAuth(holder: did, options: JSON.encode(proofOptions), jwk: key)
    let verifyOptions = [
      "proofPurpose": "assertionMethod",
      "challenge": challenge,
    ]
    let verifyResult = try XCTUnwrap(
      JSON.decode(DIDKit.verifyPresentation(presentation: vp, options: JSON.encode(verifyOptions)))
        as? [String: Any])
    let errors = try XCTUnwrap(verifyResult["errors"] as? [Any])
    XCTAssertTrue(errors.isEmpty)
  }
}

// MARK: - Test Helpers

enum JSON {
  static func encode(_ object: Any) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: object, options: [])
    return String(data: data, encoding: .utf8) ?? ""
  }

  static func decode(_ string: String) throws -> Any {
    let data = string.data(using: .utf8) ?? Data()
    return try JSONSerialization.jsonObject(with: data, options: [])
  }
}
