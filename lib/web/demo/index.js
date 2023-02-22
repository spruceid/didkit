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

  const sampleRaw = {
    "@context": "https://www.w3.org/2018/credentials/v1",
    id: "http://example.org/credentials/3731",
    type: ["VerifiableCredential"],
    issuer: did,
    issuanceDate: "2020-08-19T21:41:50Z",
    credentialSubject: {
      id: other.did,
    },
  }

  const sakazukiRaw = {
    id: "urn:uuid:042e9260-a0d3-4db6-81bd-05498c8866d1",
    name: "EXAMPLE INSTITUTE OF TECHNOLOGY Degree Credential",
    type: ["VerifiableCredential", "EducationalCredential"],
    issuer: "did:pkh:eip155:1:0xB1E26E659193AA8Cfa18d59DC5033Ad78dahoge5",
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1",
      "https://schema.sakazuki.xyz/credentials/v1.0.jsonld"
    ],
    description: "upon the recommendation of the graduate school of engineering hereby confers\n卒業おめでとうございます",
    issuanceDate: "2022-11-24T00:00:00.000Z",
    credentialSchema: {
      id: "https://schema.sakazuki.xyz/credentials/edu/v1.0.json",
      type: "JsonSchemaValidator2018"
    },
    credentialStatus: {
      id: "https://localhost:3001/api/credential-status-lists/d3c78mij26xvs4rssnvxw0z4#34",
      type: "StatusList2021Entry",
      statusPurpose: "revocation",
      statusListIndex: 34,
      statusListCredential: "https://localhost:3001/api/credential-status-lists/d3c78mij26xvs4rssnvxw0z4"
    },
    credentialSubject: {
      id: "did:pkh:eip155:1:0xB1E26E659193AA8Cfa18d59DC5033Ad78dahoge5",
      name: "hoge太郎5",
      type: "EducationalCredentialSubject",
      degree: {
        id: "No.00004",
        degreeOf: "Bachelor of engineering",
        facultyOf: "Faculty of Creative Engineering",
        dateEarned: "2022-11-24T00:00:00.000Z",
        departmentOf: "Department of Design"
      }
    }
  }

  const signing_data = generateCredentialDataToSign(
    JSON.stringify(sampleRaw),
    JSON.stringify({
      proofPurpose: "assertionMethod",
      proofFormat: "jwt",
      verificationMethod: verificationMethod,
    }),
    "ES256K",
    verificationMethod
  );

  console.log("signing_dataの中身確認");
  console.log(signing_data);

  var enc = new TextEncoder();
  const sigHash = await secp.utils.sha256(enc.encode(signing_data));
  const der_signature = await secp.sign(sigHash, privKey);
  const signature = await secp.Signature.fromDER(der_signature).toCompactHex();
  console.log("signatureの中身確認");
  console.log(signature);

  const credential = finalizeCredential(signing_data, signature);
  console.log("credentialの中身確認");
  console.log(credential);

  const verifyStr = await verifyCredential(
    credential,
    JSON.stringify({
      proofPurpose: "assertionMethod",
      proofFormat: "jwt",
    })
  );

  const verify = JSON.parse(verifyStr);
  console.log("verifyの中身確認");
  console.log(verify);

  if (verify.errors.length > 0) throw verify.errors;
})();
