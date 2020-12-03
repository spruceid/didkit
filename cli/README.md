# DIDKit CLI

DIDKit offers its functionality in a command-line program, `didkit`.

## Build

```sh
$ cargo build
```

## Install
```sh
$ cargo install --path .
```

## Commands

### `didkit help`

Output help about `didkit` and its subcommands.

### `didkit generate-ed25519-key`

Generate a Ed25519 keypair and output it in [JWK format](https://tools.ietf.org/html/rfc8037#appendix-A.1).

### `didkit key-to-did-key`

Given a [JWK][], output the corresponding [did:key][].

Currently, this only supports [Ed25519](https://tools.ietf.org/html/rfc8037#appendix-A.2) keys.

### `didkit key-to-verification-method`

Given a Ed25519 [JWK][], output the corresponding [did:key][] [verificationMethod][].

#### Options

- `-k, --key-path <file>` (required, conflicts with jwk) - Filename of JWK file
- `-j, --jwk <jwk>` (required, conflicts with key-path) - JWK.

### `didkit vc-issue-credential`

Issue a verifiable credential. Reads credential on stdin, constructs a [linked data proof][ld-proofs] to add to the credential, and outputs the resulting verifiable credential.

Corresponds to [/issue/credentials](https://w3c-ccg.github.io/vc-http-api/#/Issuer/issueCredential) in [vc-http-api][].

The proof type is set automatically based on the key file provided. JWK parameters besides the cryptographic components, such as [kid][] (Key ID), are ignored currently. For an RSA key, the [alg][] (Algorithm) parameter is ignored and `RS256` is used for it, for [RsaSignature2018][].

#### Options

Options besides `--key-path` correspond to linked data [proof options][] as specified in [ld-proofs][] and [vc-http-api][].

- `-C, --challenge <challenge>` - [challenge][] property of the proof
- `-c, --created <created>` - [created][] property of the proof. ISO8601 datetime. Defaults to the current time.
  time.
- `-d, --domain <domain>` - [domain][] property of the proof
- `-k, --key-path <key>` (required, conflicts with jwk) - Filename of JWK for signing.
- `-j, --jwk <jwk>` (required, conflicts with key-path) - JWK for signing.
- `-p, --proof-purpose <proof-purpose>` [proofPurpose][] property of the proof.
- `-v, --verification-method <verification-method>` [verificationMethod][]
  property of the proof. URI for proof verification information, e.g. a public key identifier.

#### Supported [JWK key types][kty]

- `RSA`
- `OKP` (`curve`: `Ed25519`)

### `didkit vc-verify-credential`

Verify a verifiable credential. Reads verifiable credential on standard input, and outputs verification result. Returns exit status zero if credential successfully verified, or non-zero if errors were encountered.

Corresponds to [/verify/credentials](https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential) in [vc-http-api][].

#### Options

Options are linked data [proof options][] as specified in [ld-proofs][] and [vc-http-api][]. If there is more than one proof present, at least one must pass all the requirements passed in the options.

- `-C, --challenge <challenge>` - The [challenge][] property of the proof must
  equal this value.
- `-c, --created <created>` - The [created][] property of the proof must be on or after the given ISO8601 datetime. Defaults to the current time. 
  time.
- `-d, --domain <domain>` - The [domain][] property of the proof must equal the
  given value.
- `-p, --proof-purpose <proof-purpose>` - The [proofPurpose][] property of the proof must equal this value.
- `-v, --verification-method <verification-method>` - The [verificationMethod][]
  property of the proof must equal this value.

#### Supported proof types

- [RsaSignature2018][]
- [Ed25519VerificationKey2018][]

#### Output

The verification result output is a `VerificationResult` JSON object as specified in [vc-http-api][]:
```json
{
  "checks": [],
  "warnings": [],
  "errors": []
}
```
Verification result properties:
- `checks` - Array of strings indicating checks completed on the credential.
- `warnings` - Array of warnings encountered during validation or verification.
- `errors` - Array of strings indicating errors encountered during validation or verification. If `errors` is empty, the credential is verified.

### `didkit vc-issue-presentation`

Issue a verifiable presentation. Reads presentation on stdin, generates proof to add to it, and outputs the resulting verifiable presentation.

Corresponds to [/prove/presentations](https://w3c-ccg.github.io/vc-http-api/#/Holder/provePresentation) in [vc-http-api][].

Options are the same as for [didkit vc-issue-credential](#didkit-vc-issue-credential).

### `didkit vc-verify-presentation`

Verify a verifiable presentation. Reads verifiable presentation on stdin, and outputs verification result. Returns exit status zero if presentation successfully verified, or non-zero if errors were encountered.

Corresponds to [/verify/presentations](https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyPresentation) in [vc-http-api][].

Options and output format are the same as for [didkit vc-verify-credential](#didkit-vc-verify-credential).

## Examples

See the included [shell script](tests/example.sh).

[JWK]: https://tools.ietf.org/html/rfc7517
[ld-proofs]: https://w3c-ccg.github.io/ld-proofs/
[vc-http-api]: https://w3c-ccg.github.io/vc-http-api/
[RsaSignature2018]: https://w3c-ccg.github.io/lds-rsa2018/
[Ed25519VerificationKey2018]: https://w3c-ccg.github.io/lds-ed25519-2018/

[did:key]: https://w3c-ccg.github.io/did-method-key/

[proof options]: https://w3c-ccg.github.io/ld-proofs/#dfn-proof-options
[ld-proofs-overview]: https://w3c-ccg.github.io/ld-proofs/#linked-data-proof-overview

[created]: https://w3c-ccg.github.io/security-vocab/#created
[proofPurpose]: https://w3c-ccg.github.io/security-vocab/#proofPurpose
[created]: https://www.dublincore.org/specifications/dublin-core/dcmi-terms/terms/created/
[challenge]: https://w3c-ccg.github.io/security-vocab/#challenge
[domain]: https://w3c-ccg.github.io/security-vocab/#domain
[verificationMethod]: https://w3c-ccg.github.io/security-vocab/#verificationMethod
[kty]: https://tools.ietf.org/html/rfc7517#section-4.1
[kid]: https://tools.ietf.org/html/rfc7517#section-4.5
[alg]: https://tools.ietf.org/html/rfc7517#section-4.4
