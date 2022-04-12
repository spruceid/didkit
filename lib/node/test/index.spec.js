const DIDKit = require("..");
const uuid = require("uuid").v4;

const key = {
  kty: "OKP",
  crv: "Ed25519",
  x: "PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I",
  d: "n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI",
};

describe("basic", () => {
  it("should get library version", () => {
    expect(typeof DIDKit.getVersion()).toEqual("string");
  });

  it("should generate ed25519 key", () => {
    const key = DIDKit.generateEd25519Key();

    expect(key).toHaveProperty("kty", "OKP");
    expect(key).toHaveProperty("crv", "Ed25519");
    expect(key).toHaveProperty("x");
    expect(key).toHaveProperty("d");
  });
});

describe("key", () => {
  it("should produce did", () => {
    expect(DIDKit.keyToDID("key", key)).toEqual(
      "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK"
    );
  });

  it("should produce verificationMethod", () => {
    expect(DIDKit.keyToVerificationMethod("key", key)).toEqual(
      "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK#z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK"
    );
  });
});

describe("credential", () => {
  var did, verificationMethod;

  beforeAll(() => {
    did = DIDKit.keyToDID("key", key);
    verificationMethod = DIDKit.keyToVerificationMethod("key", key);
  });

  it("should fail if parameters are empty objects", () => {
    expect(() => {
      DIDKit.issueCredential({}, {}, {});
    }).toThrow();
  });

  it("should verify issued credential", () => {
    const credential = DIDKit.issueCredential(
      {
        "@context": "https://www.w3.org/2018/credentials/v1",
        id: "http://example.org/credentials/3731",
        type: ["VerifiableCredential"],
        issuer: did,
        issuanceDate: "2020-08-19T21:41:50Z",
        credentialSubject: {
          id: "did:example:d23dd687a7dc6787646f2eb98d0",
        },
      },
      {
        proofPurpose: "assertionMethod",
        verificationMethod: verificationMethod,
      },
      key
    );

    const verifyResult = DIDKit.verifyCredential(credential, {
      proofPurpose: "assertionMethod",
    });

    expect(verifyResult["errors"].length).toBe(0);
  });
});

describe("presentation", () => {
  var did, verificationMethod;

  beforeAll(() => {
    did = DIDKit.keyToDID("key", key);
    verificationMethod = DIDKit.keyToVerificationMethod("key", key);
  });

  it("should fail if parameters are empty objects", () => {
    expect(() => {
      DIDKit.issuePresentation({}, {}, {});
    }).toThrow();
  });

  it("should verify issued presentation", () => {
    const presentation = DIDKit.issuePresentation(
      {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        id: "http://example.org/presentations/3731",
        type: ["VerifiablePresentation"],
        holder: did,
        verifiableCredential: {
          "@context": "https://www.w3.org/2018/credentials/v1",
          id: "http://example.org/credentials/3731",
          type: ["VerifiableCredential"],
          issuer: "did:example:30e07a529f32d234f6181736bd3",
          issuanceDate: "2020-08-19T21:41:50Z",
          credentialSubject: {
            id: "did:example:d23dd687a7dc6787646f2eb98d0",
          },
        },
      },
      {
        proofPurpose: "authentication",
        verificationMethod: verificationMethod,
      },
      key
    );

    const verifyResult = DIDKit.verifyPresentation(presentation, {
      proofPurpose: "authentication",
    });

    expect(verifyResult["errors"].length).toBe(0);
  });
});

describe("DIDAuth", () => {
  var did, verificationMethod;

  beforeAll(() => {
    did = DIDKit.keyToDID("key", key);
    verificationMethod = DIDKit.keyToVerificationMethod("key", key);
  });

  it("should fail if parameters are empty", () => {
    expect(() => {
      DIDKit.DIDAuth("", {}, {});
    }).toThrow();
  });

  it("should issue and verify DIDAuth verifiable presentation", () => {
    const challenge = uuid();
    const presentation = DIDKit.DIDAuth(
      did,
      {
        proofPurpose: "authentication",
        verificationMethod,
        challenge
      },
      key
    );

    const verifyResult = DIDKit.verifyPresentation(presentation, {
      proofPurpose: "authentication",
      challenge
    });

    expect(verifyResult["errors"].length).toBe(0);
  });
});

describe("DID Resolution", () => {
  it("should resolve DID to DID document", () => {
    const did = "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK";
    const result = DIDKit.didResolve(did, {});
    expect(result).toHaveProperty("didDocument");
    expect(result.didDocument.id).toEqual(did);
    expect(result).toHaveProperty("didResolutionMetadata");
    expect(result).toHaveProperty("didDocumentMetadata");
  });
});
