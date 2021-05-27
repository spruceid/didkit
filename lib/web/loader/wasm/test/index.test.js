const test = async (title, fn) => {
  try {
    await fn();
    console.log(`[    ok: ${title}]`);
  } catch (e) {
    console.error(`[fail: ${title}]`, e);
  }
};

DIDKitLoader.loadDIDKit("/didkit_wasm_bg.wasm").then(
  async ({
    getVersion,
    generateEd25519Key,
    keyToDID,
    keyToVerificationMethod,
    issueCredential,
    verifyCredential,
    issuePresentation,
    verifyPresentation,
    DIDAuth,
    resolveDID,
    JWKFromTezos,
  }) => {
    const emptyObj = JSON.stringify({});

    test("should get library version", () => {
      const version = getVersion();
      if (typeof version !== "string") throw "version is not an string";
    });

    test("should generate ed25519 key", () => {
      const k = JSON.parse(generateEd25519Key());

      if (!("kty" in k)) throw "missing 'kty' prop";
      if (!("crv" in k)) throw "missing 'kty' prop";
      if (!("x" in k)) throw "missing 'kty' prop";
      if (!("d" in k)) throw "missing 'kty' prop";

      if (k.kty !== "OKP") throw "expected 'OKP' in 'kty'";
      if (k.crv !== "Ed25519") throw "expected 'Ed25519 in 'kty'";
    });

    const key = {
      kty: "OKP",
      crv: "Ed25519",
      x: "PBcY2yJ4h_cLUnQNcYhplu9KQQBNpGxP4sYcMPdlu6I",
      d: "n5WUFIghmRYZi0rEYo2lz-Zg2B9B1KW4MYfJXwOXfyI",
    };

    const keyStr = JSON.stringify(key);

    test("should produce did", () => {
      const expect = "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK";
      const did = keyToDID("key", keyStr);
      if (did !== expect) throw `expected '${expect}'`;
    });

    test("should produce verificationMethod", async () => {
      const expect =
        "did:key:z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK#z6MkiVpwA241guqtKWAkohHpcAry7S94QQb6ukW3GcCsugbK";
      const vm = await keyToVerificationMethod("key", keyStr);
      if (vm !== expect) throw `expected '${expect}'`;
    });

    const did = keyToDID("key", keyStr);
    const verificationMethod = await keyToVerificationMethod("key", keyStr);

    const other = await (async () => {
      const keyStr = generateEd25519Key();
      const key = JSON.parse(keyStr);
      const did = keyToDID("key", keyStr);
      const verificationMethod = await keyToVerificationMethod("key", keyStr);

      return {key, keyStr, did, verificationMethod};
    })();

    test("should fail if parameters are empty objects", async () => {
      try {
        await issueCredential(emptyObj, emptyObj, emptyObj);
        throw "did not fail";
      } catch (e) {
        return;
      }
    });

    test("should verify issued credential (LDP)", async () => {
      const credential = await issueCredential(
        JSON.stringify({
          "@context": "https://www.w3.org/2018/credentials/v1",
          id: "http://example.org/credentials/3731",
          type: ["VerifiableCredential"],
          issuer: did,
          issuanceDate: "2020-08-19T21:41:50Z",
          credentialSubject: {
            id: other.did,
          },
        }),
        JSON.stringify({
          proofPurpose: "assertionMethod",
          verificationMethod: verificationMethod,
        }),
        keyStr
      );

      const verifyStr = await verifyCredential(
        credential,
        JSON.stringify({
          proofPurpose: "assertionMethod",
        })
      );

      const verify = JSON.parse(verifyStr);

      if (verify.errors.length > 0) throw verify.errors;
    });

    test("should verify issued credential (JWT)", async () => {
      const credential = await issueCredential(
        JSON.stringify({
          "@context": "https://www.w3.org/2018/credentials/v1",
          id: "http://example.org/credentials/3731",
          type: ["VerifiableCredential"],
          issuer: did,
          issuanceDate: "2020-08-19T21:41:50Z",
          credentialSubject: {
            id: other.did,
          },
        }),
        JSON.stringify({
          proofPurpose: "assertionMethod",
          proofFormat: "jwt",
          verificationMethod: verificationMethod,
        }),
        keyStr
      );

      const verifyStr = await verifyCredential(
        credential,
        JSON.stringify({
          proofPurpose: "assertionMethod",
          proofFormat: "jwt",
        })
      );

      const verify = JSON.parse(verifyStr);

      if (verify.errors.length > 0) throw verify.errors;
    });

    test("should fail if parameters are empty objects", async () => {
      try {
        await issuePresentation(emptyObj, emptyObj, emptyObj);
        throw "did not fail";
      } catch (e) {
        return;
      }
    });

    test("should verify issued presentation (LDP VC in LDP VP)", async () => {
      const credential = JSON.parse(
        await issueCredential(
          JSON.stringify({
            "@context": "https://www.w3.org/2018/credentials/v1",
            id: "http://example.org/credentials/3731",
            type: ["VerifiableCredential"],
            issuer: did,
            issuanceDate: "2020-08-19T21:41:50Z",
            credentialSubject: {
              id: other.did,
            },
          }),
          JSON.stringify({
            proofPurpose: "assertionMethod",
            verificationMethod: verificationMethod,
          }),
          keyStr
        )
      );

      const presentation = await issuePresentation(
        JSON.stringify({
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          id: "http://example.org/presentations/3731",
          type: ["VerifiablePresentation"],
          holder: other.did,
          verifiableCredential: credential,
        }),
        JSON.stringify({
          proofPurpose: "authentication",
          verificationMethod: other.verificationMethod,
        }),
        other.keyStr
      );

      const verifyStr = await verifyPresentation(
        presentation,
        JSON.stringify({
          proofPurpose: "authentication",
        })
      );

      const verify = JSON.parse(verifyStr);

      if (verify.errors.length > 0) throw verify.errors;
    });

    test("should verify issued presentation (LDP VC in JWT VP)", async () => {
      const credential = JSON.parse(
        await issueCredential(
          JSON.stringify({
            "@context": "https://www.w3.org/2018/credentials/v1",
            id: "http://example.org/credentials/3731",
            type: ["VerifiableCredential"],
            issuer: did,
            issuanceDate: "2020-08-19T21:41:50Z",
            credentialSubject: {
              id: other.did,
            },
          }),
          JSON.stringify({
            proofPurpose: "assertionMethod",
            verificationMethod: verificationMethod,
          }),
          keyStr
        )
      );

      const presentation = await issuePresentation(
        JSON.stringify({
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          id: "http://example.org/presentations/3731",
          type: ["VerifiablePresentation"],
          holder: other.did,
          verifiableCredential: credential,
        }),
        JSON.stringify({
          proofPurpose: "authentication",
          proofFormat: "jwt",
          verificationMethod: other.verificationMethod,
        }),
        other.keyStr
      );

      const verifyStr = await verifyPresentation(
        presentation,
        JSON.stringify({
          proofPurpose: "authentication",
          proofFormat: "jwt",
        })
      );

      const verify = JSON.parse(verifyStr);

      if (verify.errors.length > 0) throw verify.errors;
    });

    test("should verify issued presentation (JWT VC in LDP VP)", async () => {
      const credential = await issueCredential(
        JSON.stringify({
          "@context": "https://www.w3.org/2018/credentials/v1",
          id: "http://example.org/credentials/3731",
          type: ["VerifiableCredential"],
          issuer: did,
          issuanceDate: "2021-06-09T18:41:27Z",
          credentialSubject: {
            id: other.did,
          },
        }),
        JSON.stringify({
          proofPurpose: "assertionMethod",
          proofFormat: "jwt",
          verificationMethod: verificationMethod,
        }),
        keyStr
      );

      const presentation = await issuePresentation(
        JSON.stringify({
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          id: "http://example.org/presentations/3731",
          type: ["VerifiablePresentation"],
          holder: other.did,
          verifiableCredential: credential,
        }),
        JSON.stringify({
          proofPurpose: "authentication",
          verificationMethod: other.verificationMethod,
        }),
        other.keyStr
      );

      const verifyStr = await verifyPresentation(
        presentation,
        JSON.stringify({
          proofPurpose: "authentication",
        })
      );

      const verify = JSON.parse(verifyStr);

      if (verify.errors.length > 0) throw verify.errors;
    });

    test("should verify issued presentation (JWT VC in JWT VP)", async () => {
      const credential = await issueCredential(
        JSON.stringify({
          "@context": "https://www.w3.org/2018/credentials/v1",
          id: "http://example.org/credentials/3731",
          type: ["VerifiableCredential"],
          issuer: did,
          issuanceDate: "2021-06-09T18:41:27Z",
          credentialSubject: {
            id: other.did,
          },
        }),
        JSON.stringify({
          proofPurpose: "assertionMethod",
          proofFormat: "jwt",
          verificationMethod: verificationMethod,
        }),
        keyStr
      );

      const presentation = await issuePresentation(
        JSON.stringify({
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          id: "http://example.org/presentations/3731",
          type: ["VerifiablePresentation"],
          holder: other.did,
          verifiableCredential: credential,
        }),
        JSON.stringify({
          proofPurpose: "authentication",
          proofFormat: "jwt",
          verificationMethod: other.verificationMethod,
        }),
        other.keyStr
      );

      const verifyStr = await verifyPresentation(
        presentation,
        JSON.stringify({
          proofPurpose: "authentication",
          proofFormat: "jwt",
        })
      );

      const verify = JSON.parse(verifyStr);

      if (verify.errors.length > 0) throw verify.errors;
    });

    test("should issue and verify DIDAuth presentation (LDP)", async () => {
      const challenge = Math.random().toString(16).substr(2);
      const verifiablePresentation = JSON.parse(
        await DIDAuth(
          did,
          JSON.stringify({
            proofPurpose: "authentication",
            challenge,
            verificationMethod,
          }),
          keyStr
        )
      );

      const verifyStr = await verifyPresentation(
        JSON.stringify(verifiablePresentation),
        JSON.stringify({
          proofPurpose: "authentication",
          challenge,
        })
      );

      const verify = JSON.parse(verifyStr);

      if (verify.errors.length > 0) throw verify.errors;
    });

    test("should issue and verify DIDAuth presentation (JWT)", async () => {
      const challenge = Math.random().toString(16).substr(2);
      const verifiablePresentation = await DIDAuth(
        did,
        JSON.stringify({
          proofPurpose: "authentication",
          proofFormat: "jwt",
          challenge,
          verificationMethod,
        }),
        keyStr
      );

      const verifyStr = await verifyPresentation(
        verifiablePresentation,
        JSON.stringify({
          proofPurpose: "authentication",
          proofFormat: "jwt",
          challenge,
        })
      );

      const verify = JSON.parse(verifyStr);

      if (verify.errors.length > 0) throw verify.errors;
    });

    test("should resolve did:tz", async () => {
      await resolveDID("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq", JSON.stringify({}));
    });

    test("should resolve did:web", async () => {
      await resolveDID("did:web:vc.transmute.world", JSON.stringify({}));
    });

    test("should convert edpk to JWK", async () => {
      const jwkStr = await JWKFromTezos("edpkuxZ5AQVCeEJ9inUG3w6VFhio5KBwC22ekPLBzcvub3QY2DvJ7n");
      const jwk = JSON.parse(jwkStr);
      if (jwk.crv !== "Ed25519") throw jwk.crv;
      if (jwk.x !== "rVEB0Icbomw1Ir-ck52iCZl1SICc5lCg2pxI8AmydDw") throw jwk.x;
    });
  }
);
