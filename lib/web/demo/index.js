import init, {
  keyToDID,
  pubkeyToDID,
  keyToVerificationMethod,
  verifyCredential,
  generateCredentialDataToSign,
  finalizeCredential,
  didToVerificationMethod,
} from "./pkg/web/didkit_wasm.js";

const secp = window.nobleSecp256k1;

const privKey = secp.utils.hexToBytes(
  "910e629f10bfe69fc70fc63b7bc6cc2d6b9d4af22fcd277696e07ce4cb936e61"
);
const pubKey = secp.getPublicKey(privKey);

(async () => {
  await init();
  const did = pubkeyToDID("key", secp.utils.bytesToHex(pubKey));
  const verificationMethod = await didToVerificationMethod(did);

  const other = await (async () => {
    const keyStr =
      '{"kty":"EC","crv":"secp256k1","x":"X7ZzK9t8i6LZgi7lcKGXLMzeV9PLH2NIPNip_g_8eso","y":"cqZciccFbybaKHxKMm8em48rSH26Cm0peOvNwvelVgM","d":"NSf9zygkwE2UoJMlzs-nf0UnIYju_d_cVG2we1EKZOQ"}';
    const key = JSON.parse(keyStr);
    const did = keyToDID("key", keyStr);
    const verificationMethod = await keyToVerificationMethod("key", keyStr);

    return { key, keyStr, did, verificationMethod };
  })();


  const signing_data = generateCredentialDataToSign(
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
    "ES256K",
    verificationMethod
  );

  var enc = new TextEncoder();
  const sigHash = await secp.utils.sha256(enc.encode(signing_data));
  const der_signature = await secp.sign(sigHash, privKey);
  const signature = await secp.Signature.fromDER(der_signature).toCompactHex();

  const credential = finalizeCredential(signing_data, signature);

  const verifyStr = await verifyCredential(
    credential,
    JSON.stringify({
      proofPurpose: "assertionMethod",
      proofFormat: "jwt",
    })
  );

  const verify = JSON.parse(verifyStr);

  if (verify.errors.length > 0) throw verify.errors;
})();
