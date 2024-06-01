module.exports = {
  settings: {
    // don't test live implementations
    enableInteropTests: false,
    testAllImplementations: false
  },
  implementations: [{
    "name": "Spruce",
    "implementation": "Spruce",
    "issuers": [{
      "id": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
      "endpoint": "https://127.0.0.1:9000/credentials/issue",
      "options": {
        "type": "Ed25519Signature2020"
      },
      "supports": {
        "vc": ['1.1', '2.0']
      },
      "tags": ["vc-api", "Ed25519Signature2020", "JWT", "vc2.0"]
    }, {
      "id": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
      "endpoint": "https://127.0.0.1:9000/credentials/issue",
      "options": {
        "type": "DataIntegrityProof"
      },
      "supports": {
        "vc": ['1.1', '2.0']
      },
      "tags": ["vc-api", "eddsa-rdfc-2022", "eddsa-jcs-2022", "JWT", "vc2.0"]
    }],
    "verifiers": [{
      "id": "https://spruceid.com",
      "endpoint": "https://127.0.0.1:9000/credentials/verify",
      "supportedEcdsaKeyTypes": ["P-256"],
      "tags": ["vc-api", "Ed25519Signature2020", "JWT", "eddsa-rdfc-2022", "eddsa-jcs-2022", "vc2.0"]
    }],
    "vpVerifiers": [{
      "id": "https://spruceid.com",
      "endpoint": "https://127.0.0.1:9000/presentations/verify",
      "supportedEcdsaKeyTypes": ["P-256"],
      "tags": ["vc-api", "Ed25519Signature2020", "JWT", "eddsa-rdfc-2022", "eddsa-jcs-2022", "vc2.0"]
    }],
    "didResolvers": [{
      "id": "https://spruceid.com",
      "endpoint": "https://127.0.0.1:9000/identifiers",
      "tags": ["did-key"]
    }]
  }]
};
