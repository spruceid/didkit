# didkit-node

Node native bindings generated with `neon-bindings`.

API follows the same options as the CLI library, accepting plain old Javascript
objects, automatically parsing and validating them in the native code, throwing
an error if the format is incorrect.

Please refer to the [CLI docs][] for more information about the functions.

## Getting Started

```js
// Import the module
const DIDKit = require('didkit');

console.log(DIDKit.getVersion());

// To issue credentials and presentations, you need a key.
// The library provides a function to generate one.
const key = DIDKit.generateEd25519Key();

// There are two helpful functions to obtain a DID and the `did:key`
// `verificationMethod` from the key.
const did = DIDKit.keyToDID('key', key);
const verificationMethod = DIDKit.keyToVerificationMethod('key', key);
```

### Issuing a Credential

After setting everthing up as shown in the first section, you can start issuing
credentials.

```js
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
```

## Options

- `DIDKit.issueCredential(credential, options, key)`
- `DIDKit.verifyCredential(vc, options)`
- `DIDKit.issuePresentation(presentation, options, key)`
- `DIDKit.verifyPresentation(vp, options)`

The CLI options are available as the second argument of the issue and verify
functions, and expect a regular Javascript object where each top-level property
corresponds to an available option for that function, as shown in the example
below. The available options for each function can be found in the
[CLI docs][].

```js
{
  challenge: '...',
  domain: '...',
  proofPurpose: '...',
  verificationMethod: '...',
}
```

### Resolving DIDs

[DID Resolution](https://www.w3.org/TR/did-core/#did-resolution) resolves a
DID, with [DID Resolution options](https://www.w3.org/TR/did-core/#did-resolution-options),
to a DID Resolution Result ([ResolutionResult](https://w3c-ccg.github.io/did-resolution/#did-resolution-result)
structure). The DID Resultion Result includes the resolved DID document, along with
[DID resolution metadata](https://www.w3.org/TR/did-core/#did-resolution-metadata)
and [DID document metadata](https://www.w3.org/TR/did-core/#did-document-metadata).
This result is equivalent to what [DIDKit CLI][CLI docs] returns when using the
`-m` (`--with-metadata`) option (`didkit did-resolve -m <did>`).

- `DIDKit.didResolutionResult(did, resolutionOptions)`

```js
const did = 'did:web:identity.foundation';
const resolutionOptions = {};
const didResolutionResult = DIDKit.didResolve(did, resolutionOptions);
console.log(didResolutionResult)
```
Output:
```js
{
  '@context': 'https://w3id.org/did-resolution/v1',
  didDocument: {
    '@context': [ 'https://www.w3.org/ns/did/v1' ],
    id: 'did:web:identity.foundation'
  },
  didResolutionMetadata: {},
  didDocumentMetadata: {}
}
```

[CLI docs]: https://github.com/spruceid/didkit/blob/main/cli/README.md
