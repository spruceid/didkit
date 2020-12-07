# didkit-node

Node native bindings generated with `neon-bindings`.

API follows the same options as the CLI library, accepting plain old Javascript
objects, automatically parsing and validating them in the native code, throwing
an error if the format is incorrect.

Please refer to [https://github.com/spruceid/didkit/tree/main/cli](the CLI docs)
for more information about the functions.

## Options

- `DIDKit.issueCredential(credential, options, key)`
- `DIDKit.verifyCredential(vc, options)`
- `DIDKit.issuePresentation(presentation, options, key)`
- `DIDKit.verifyPresentation(vp, options)`

The CLI options are available as the second argument of the issue and verify
functions, and expect a regular Javascript object where each top-level property
corresponds to an available option for that function, as shown in the example
below.

```js
{
  challenge: '...',
  domain: '...',
  proofPurpose: '...',
  verificationMethod: '...',
}
```
