module.exports = [{
  "name": "Spruce",
  "implementation": "Spruce",
  "issuers": [{
    "id": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
    "endpoint": "https://127.0.0.1:9000/credentials/issue",
    "options": {
      "type": "Ed25519Signature2020"
    },
    "tags": ["vc-api", "Ed25519Signature2020", "JWT"]
  }, {
    "id": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
    "endpoint": "https://127.0.0.1:9000/credentials/issue",
    "options": {
      "type": "DataIntegrityProof"
    },
    "tags": ["vc-api", "eddsa-2022", "JWT"]
  }],
  "verifiers": [{
    "id": "https://spruceid.com",
    "endpoint": "https://127.0.0.1:9000/credentials/verify",
    "tags": ["vc-api", "Ed25519Signature2020", "JWT", "eddsa-2022"]
  }],
  "didResolvers": [{
    "id": "https://spruceid.com",
    "endpoint": "https://127.0.0.1:9000/identifiers",
    "tags": ["did-key"]
  }]
}];
