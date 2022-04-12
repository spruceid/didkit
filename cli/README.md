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

### `didkit key-to-did <method_pattern>`

Given a [JWK][] and a supported DID method name or pattern, output the corresponding DID.

### `didkit key-to-verification-method <method_pattern>`

Given a [JWK][] and a supported DID method name or pattern, output the corresponding [verificationMethod][].

#### Options

- `-k, --key-path <file>` (required, conflicts with jwk) - Filename of JWK file
- `-j, --jwk <jwk>` (required, conflicts with key-path) - JWK.

#### Supported DID method names and patterns

- `key` - [did:key][] ([Ed25519][], [P-256][] [Secp256k1][])
- `tz` - [did:tz][] ([Ed25519][], [P-256][] [Secp256k1][])
- `ethr` - [did:ethr][] ([Secp256k1][])
- `sol` - `did:sol` ([Ed25519][])
- `pkh:[…]` - `did:pkh` ([Ed25519][], [P-256][] [Secp256k1][])

### `didkit vc-issue-credential`

Issue a verifiable credential. Reads credential on stdin, constructs a [linked data proof][ld-proofs] to add to the credential, and outputs the resulting verifiable credential.

Corresponds to [/credentials/issue](https://w3c-ccg.github.io/vc-api/#issue-credential) in [vc-http-api][].

The proof type is set automatically based on the key file provided. JWK parameters besides the cryptographic components, such as [kid][] (Key ID), are ignored currently. For an RSA key, the [alg][] (Algorithm) parameter is ignored and `RS256` is used for it, for [RsaSignature2018][].

#### Options

- `-r, --did-resolver <url>` - [DID resolver HTTP(S) endpoint][did-resolution-https-binding], used for DID resolution and DID URL dereferencing for non-built-in DID Methods. Equivalent to environmental variable `DID_RESOLVER`.
- `-R, --did-resolver-override <url>` - [DID resolver HTTP(S) endpoint][did-resolution-https-binding], used for DID resolution and DID URL dereferencing for all DID Methods. Equivalent to environmental variable `DID_RESOLVER_OVERRIDE`.
- `-k, --key-path <file>` - Filename of JWK file for signing. Conflicts with `-j`.
- `-j, --jwk <jwk>` - JWK for signing. Conflicts with `-k`.
- `-S, --ssh-agent` - Use SSH agent for signing instead of JWK private key. See the section on SSH Agent below for more info.

One of `-k` (`--key-path`), `-j` (`--jwk`) or `-S` (`--ssh-agent`) is required.

The following options correspond to linked data [proof options][] as specified in [ld-proofs][] and [vc-http-api][]:

- `-t, --type <type>` - `type` of proof object to create.
- `-C, --challenge <challenge>` - [challenge][] property of the proof
- `-c, --created <created>` - [created][] property of the proof. ISO8601 datetime. Defaults to the current time.
  time.
- `-d, --domain <domain>` - [domain][] property of the proof
- `-p, --proof-purpose <proof-purpose>` [proofPurpose][] property of the proof.
- `-v, --verification-method <verification-method>` [verificationMethod][]
  property of the proof. URI for proof verification information, e.g. a public key identifier.

#### Supported [JWK key types][kty]

- `RSA`
- `OKP` (`curve`: `Ed25519`)

#### SSH Agent

DIDKit can use [SSH Agent][] for signing, as an alternative to signing with a JWK private key.
If the `-S` (`--ssh-agent`) CLI option is used, DIDKit will attempt to connect to a local instance of `ssh-agent`, via the [UNIX socket][] refered to by environmental variable `SSH_AUTH_SOCK`, following the [SSH Agent Protocol][].

##### Key selection

When `-S` (`--ssh-agent`) is used, the JWK referred to by `-k` (`--key-file`) or `-j` (`--jwk`) is treated as a public key and used to select which key from SSH Agent to use for signing. If no JWK option is used, then the SSH Agent is expected to have only one key, and that key is used for signing.

[SSH Agent]: https://en.wikipedia.org/wiki/Ssh-agent
[UNIX socket]: https://en.wikipedia.org/wiki/Unix_domain_socket
[SSH Agent Protocol]: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04

### `didkit vc-verify-credential`

Verify a verifiable credential. Reads verifiable credential on standard input, and outputs verification result. Returns exit status zero if credential successfully verified, or non-zero if errors were encountered.

Corresponds to [/credentials/verify](https://w3c-ccg.github.io/vc-api/#verify-credential) in [vc-http-api][].

#### Options

- `-r, --did-resolver <url>` - [DID resolver HTTP(S) endpoint][did-resolution-https-binding], used for DID resolution and DID URL dereferencing for non-built-in DID Methods. Equivalent to environmental variable `DID_RESOLVER`.
- `-R, --did-resolver-override <url>` - [DID resolver HTTP(S) endpoint][did-resolution-https-binding], used for DID resolution and DID URL dereferencing for all DID Methods. Equivalent to environmental variable `DID_RESOLVER_OVERRIDE`.

The following options are linked data [proof options][] as specified in [ld-proofs][] and [vc-http-api][]. If there is more than one proof present, at least one must pass all the requirements passed in the options.

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

Corresponds to [/presentations/prove](https://w3c-ccg.github.io/vc-api/#prove-presentation) in [vc-http-api][].

Options are the same as for [didkit vc-issue-credential](#didkit-vc-issue-credential).

### `didkit vc-verify-presentation`

Verify a verifiable presentation. Reads verifiable presentation on stdin, and outputs verification result. Returns exit status zero if presentation successfully verified, or non-zero if errors were encountered.

Corresponds to [/presentations/verify](https://w3c-ccg.github.io/vc-api/#verify-presentation) in [vc-http-api][].

Options and output format are the same as for [didkit vc-verify-credential](#didkit-vc-verify-credential).

### `didkit did-resolve <did>`

Resolve a DID to a DID document, according to [DID Resolution][did-resolution].

#### Options
- `-m, --with-metadata` - Return a the resolved DID document with resolution metadata and document metadata, in a [DID Resolution Result][did-resolution-result] object.
- `-i <name=value>` - A [DID Resolution input metadata][did-resolution-input-metadata] property. If `=` is omitted, boolean `true` is used as the value, otherwise, value is a string. May be repeated to add multiple properties. If used multiple times with the same `name`, the values are combined into an array value to form a single property.
- `-r, --did-resolver <url>` - [DID resolver HTTP(S) endpoint][did-resolution-https-binding], used for DID resolution and DID URL dereferencing for non-built-in DID Methods. Equivalent to environmental variable `DID_RESOLVER`.
- `-R, --did-resolver-override <url>` - [DID resolver HTTP(S) endpoint][did-resolution-https-binding], used for DID resolution and DID URL dereferencing for all DID Methods. Equivalent to environmental variable `DID_RESOLVER_OVERRIDE`.

#### Output
Returns the resolved DID document, optionally with metadata.

Without the `-m` option, a representation of the resolved DID document is returned, without document metadata or resolution metadata.

If the `-m` option is used, a DID Resolution Result is returned, which is a JSON object containing the following properties:
- `didDocument` - the resolved DID document
- `didResolutionMetadata` - [DID resolution metadata][did-resolution-metadata]
- `didDocumentMetadata` - [DID document metadata][did-document-metadata]
- `@context` - JSON-LD context, if using JSON-LD representation.

Exit status is zero on success, and nonzero on failure. On failure, a DID Resolution Result object may still be returned on standard output if the `-m` option is used, where the `error` property of the DID resolution metadata object is set to the error message. If `-m` is not used, the error message is returned on standnard error.

### `didkit did-dereference <did-url>`

Dereference a DID URL to a resource, as in [did-core - DID URL Dereferencing][did-url-dereferencing].

#### Options
- `-m, --with-metadata` - Return the resulting resource with resolution metadata and document metadata, in a [DID Resolution Result][did-resolution-result] object.
- `-i <name=value>` - A [DID URL Dereferencing input metadata][did-url-dereferencing-input-metadata] property. If `=` is omitted, boolean `true` is used as the value, otherwise, value is a string. May be repeated to add multiple properties. If used multiple times with the same `name`, the values are combined into an array value to form a single property.
- `-r, --did-resolver <url>` - [DID resolver HTTP(S) endpoint][did-resolution-https-binding], used for DID resolution and DID URL dereferencing for non-built-in DID Methods. Equivalent to environmental variable `DID_RESOLVER`.
- `-R, --did-resolver-override <url>` - [DID resolver HTTP(S) endpoint][did-resolution-https-binding], used for DID resolution and DID URL dereferencing for all DID Methods. Equivalent to environmental variable `DID_RESOLVER_OVERRIDE`.

#### Output
Returns the resource dereferenced from the DID URL, optionally with metadata.

Without the `-m` option, the content resulting from dereferencing is returned, without content metadata or dereferencing metadata.

If the `-m` option is used, a JSON array is returned containing the following three objects:
- The resolved DID document or other resource corresponding to the dereferenced DID URL
- [DID dereferencing metadata][did-url-dereferencing-metadata] or [DID resolution metadata][did-resolution-metadata]
- Content metadata or [DID document metadata][did-document-metadata]

Exit status is zero on success and nonzero on error. On error, if `-m` is used, the error message is returned in the `error` property of the DID dereferencing metadata object on standard output; if `-m` is not used, the error is printed on standard error.

### `didkit did-create <did-method>`

Construct a [DID method transaction][] to create a DID with a given DID method.

#### Options

- `-o <name=value>` - Options for DID Create operation.
- `-r, --recovery-key <file>` - JWK file for DID recovery and/or deactivation purposes, as used in Sidetree DID methods (e.g. `did:ion`).
- `-u, --update-key <file>` - JWK file for DID update operations, as used in Sidetree DID Methods (e.g. `did:ion`).
- `-v, --verification-key <file>` - JWK file for default verification method

#### Output

A [DID method transaction][] for a DID Create operation.

### `didkit did-update <subcommand>`

Construct a [DID method transaction][] to update a DID.

#### Options
- `-o <name=value>` - Options for DID Update operation.
- `-u, --new-update-key <file>` - New JWK file for next DID update operations, as used in Sidetree DID Methods (e.g. `did:ion`).
- `-U, --update-key <file>` - JWK file for performing this DID update operation

#### Subcommands

Updates to a DID document may be done using these `did-update` subcommands. These correspond roughly to [`didDocumentOperation`][didDocumentOperation] values in DIF DID registration and/or [DID State Patches][did-state-patches] in Sidetree.

- [`set-service`](#didkit-did-update-set-service-id)
- [`set-verification-method`](#didkit-did-update-set-verification-method-id)
- [`remove-service`](#didkit-did-update-remove-service-id)
- [`remove-verification-method`](#didkit-did-update-remove-verification-method-id)

#### Output
A [DID method transaction][] for a DID Update operation.

### `didkit did-update set-service <id>`

Construct a [DID method transaction][] to add or modify a [service][services] in a DID document.

The identified service object is created if it is exists, or reset if it does not exist, to contain the properties corresponding to the options passed, i.e. the `type` and `serviceEndpoint` properties.

#### Options
- `-d, --did <did>` - DID whose DID document to update. Default: implied from `<id>`
- `-t, --type <type>...` - Service type
- `-e, --endpoint <endpoint>...` - serviceEndpoint URI or JSON object

### `didkit did-update set-verification-method <id>`

Construct a [DID method transaction][] to add or modify a [verification method][verification-methods] in a DID document.

The identified verification method is created if it does not exist, or reset if it already exists. The verification method is constructed to contain properties as passed in the options.

#### Options
- `-c, --controller <did>` - Verification method controller property
- `-d, --did <did>` - DID whose DID document to update. Default: implied from `<id>`
- `-t, --type <type>` - Verification method type (required)

##### Verification relationship options
At least one [verification relationship][verification-relationships] (proof purpose) must be provided. Each of these options creates the respective verification relationship in the DID document for the verification method object.

- `-S, --assertionMethod` - [Assertion](https://www.w3.org/TR/did-core/#assertion)
- `-U, --authentication`- [Authentication](https://www.w3.org/TR/did-core/#authentication)
- `-D, --capabilityDelegation`- [Capability Delegation](https://www.w3.org/TR/did-core/#capability-delegation)
- `-I, --capabilityInvocation` - [Capability Invocation](https://www.w3.org/TR/did-core/#capability-invocation)
- `-K, --keyAgreement` - [keyAgreement](https://www.w3.org/TR/did-core/#key-agreement)

##### Public key options
Exactly one public key property must be provided. Which properties are allowed depends on the verification method type.
- `-j, --publicKeyJwk <JWK>` - [publicKeyJwk][] value
- `-k, --publicKeyJwkPath <filename>` - [publicKeyJwk][] value read from file
- `-m, --publicKeyMultibase <string>` - Multibase-encoded public key ([publicKeyMultibase][] value)
- `-b, --blockchainAccountId <account>` - [blockchainAccountId](https://w3c-ccg.github.io/security-vocab/#blockchainAccountId) (CAIP-10) value

### `didkit did-update remove-service <id>`

Construct a [DID method transaction][] to remove a [service][services] from a DID document.

#### Options
- `-d, --did <did>` - DID whose DID document to update. Default: implied from `<id>`

### `didkit did-update remove-verification-method <id>`

Construct a [DID method transaction][] to remove a [verification method][verification-methods] from a DID document.

#### Options
- `-d, --did <did>` - DID whose DID document to update. Default: implied from `<id>`

### `didkit did-recover <did>`

Construct a [DID method transaction][] to perform a DID recover operation ([DID recovery][did-recovery]), if supported by the DID method.

#### Options
- `-o <name=value>` - Options for DID Recover operation.
- `-r, --new-recovery-key <file>` - New JWK file for DID recovery and/or deactivation purposes, as used in Sidetree DID methods (e.g. `did:ion`).
- `-u, --new-update-key <file>` - New JWK file for next DID update operation, as used in Sidetree DID Methods (e.g. `did:ion`).
- `-v, --new-verification-key <file>` - New JWK file for default verification method
- `-R, --recovery-key <file>` - JWK file for performing this DID recover operation

#### Output

A [DID method transaction][] for a DID Recover operation.

### `didkit did-deactivate <did>`

Construct a [DID method transaction][] to deactivate a DID, if supported by the DID method.

#### Options
- `-k, --key <key>` - JWK file to perform the DID Deactivate operation
- `-o <name=value>` - Options for DID deactivate operation.

#### Output
A [DID method transaction][] for a DID Deactivate operation.

### `didkit did-from-tx`

Reads a [DID method transaction][] on standard input, and extracts or derives its DID.

#### Output

The DID corresponding to the input transaction.

### `didkit did-submit-tx <did>`

Reads a [DID method transaction][] on standard input, and submits it in a method-specific way. Returns exit status zero if the transaction was successfully submitted.

#### Output

A method-specific data structure.

## Concepts

### DID method transaction

DIDKit's DID method operation commands ([create](#didkit-did-create-did-method), [update](#didkit-did-update-subcommand), [recover](#didkit-did-recover-did), [deactivate](#didkit-did-deactivate-did)) do not fully perform the respective operation; instead, they return a data structure representing the partially applied operation, called a **DID method transaction**. The transaction is a verifiable message created by a DID controller to perform a [DID method operation][method-operations]. The transaction can be submitted, published, and/or fully performed, per the DID method, using the [did-submit-tx](#didkit-did-submit-tx-did) subcommand.

## Examples

See the included [shell script](tests/example.sh).

See also the following shell scripts demonstrating create, update, recover and deactivate operations:
- [create and update service](tests/ion-create-update-svc.sh)
- [create and update verification method](tests/ion-create-update-vm.sh)
- [create and recover](tests/ion-create-recover.sh)
- [create and deactivate](tests/ion-create-deactivate.sh)

[ssi]: https://github.com/spruceid/ssi
[JWK]: https://tools.ietf.org/html/rfc7517
[ld-proofs]: https://w3c-ccg.github.io/ld-proofs/
[vc-http-api]: https://w3c-ccg.github.io/vc-http-api/
[RsaSignature2018]: https://w3c-ccg.github.io/lds-rsa2018/
[Ed25519VerificationKey2018]: https://w3c-ccg.github.io/lds-ed25519-2018/
[Ed25519]: https://tools.ietf.org/html/rfc8037#appendix-A.2
[P-256]: https://tools.ietf.org/html/rfc7518#section-6.2.1.1
[Secp256k1]: https://tools.ietf.org/html/rfc8812#section-3.1

[did:key]: https://w3c-ccg.github.io/did-method-key/
[did:web]: https://w3c-ccg.github.io/did-method-web/
[did:tz]: https://did-tezos.spruceid.com/
[did:ethr]: https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md

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
[did-resolution]: https://w3c-ccg.github.io/did-resolution/
[did-resolution-input-metadata]: https://w3c.github.io/did-core/#did-resolution-input-metadata-properties
[did-resolution-metadata]: https://w3c.github.io/did-core/#did-resolution-metadata-properties
[did-document-metadata]: https://w3c.github.io/did-core/#did-document-metadata-properties
[did-resolution-result]: https://w3c-ccg.github.io/did-resolution/#did-resolution-result
[did-url-dereferencing]: https://w3c.github.io/did-core/#did-url-dereferencing
[did-url-dereferencing-metadata]: https://w3c.github.io/did-core/#did-url-dereferencing-metadata-properties
[did-url-dereferencing-input-metadata]: https://w3c.github.io/did-core/#did-url-dereferencing-input-metadata-properties
[did-resolution-https-binding]: https://w3c-ccg.github.io/did-resolution/#bindings-https
[method-operations]: https://www.w3.org/TR/did-core/#method-operations
[did-recovery]: https://www.w3.org/TR/did-core/#did-recovery
[verification-methods]: https://www.w3.org/TR/did-core/#verification-methods
[verification-relationships]: https://www.w3.org/TR/did-core/#verification-relationships
[services]: https://www.w3.org/TR/did-core/#services
[publicKeyJwk]: https://www.w3.org/TR/did-core/#dfn-publickeyjwk
[publicKeyMultibase]: https://www.w3.org/TR/did-core/#dfn-publickeymultibase
[DID method transaction]: #did-method-transaction
[didDocumentOperation]: https://identity.foundation/did-registration/#diddocumentoperation
[did-state-patches]: https://identity.foundation/sidetree/spec/v1.0.0/#did-state-patches
