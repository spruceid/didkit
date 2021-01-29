# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2021-01-27
[Initial release][]
### Added
- Issuing and verifying JSON-LD [Verifiable Credentials][vc-data-model] and [Verifiable Presentations][].
- [Linked data proof](https://w3c-ccg.github.io/ld-proofs/) types [RsaSignature2018](https://w3c-ccg.github.io/lds-rsa2018/) and [Ed25519Signature2018](https://w3c-ccg.github.io/lds-ed25519-2018/).
- Resolving DID methods [did:key][], [did:web][], and [did:tz][] (layer 1), for proof verification.
- Deriving [did:key][] and [did:tz][] DIDs from Ed25519 keypairs.
- Ed25519 keypair generation.
- CLI (`didkit`).
- HTTP server (`didkit-http`) implementing [vc-http-api `0.0.1`][vc-http-api-0.1.1].
- C shared library (`didkit.so`).
- Java package (`didkit.jar`).
- Android library (`didkit.aar`).
- Dart/Flutter plugin.
- Apache License, Version 2.0.
- Third-party copyright notices.

[Initial release]: https://sprucesystems.medium.com/didkit-v0-1-is-live-d0ea6638dbc9
[did:key]: https://w3c-ccg.github.io/did-method-key/
[did:web]: https://w3c-ccg.github.io/did-method-web/
[did:tz]: https://did-tezos-draft.spruceid.com/
[vc-http-api-0.1.1]: https://w3c-ccg.github.io/vc-http-api/versions/v0.0.1/
[vc-data-model]: https://w3c.github.io/vc-data-model/
[Verifiable Presentations]: https://w3c.github.io/vc-data-model/#presentations-0

[Unreleased]: https://github.com/spruceid/didkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/spruceid/didkit/releases/tag/v0.1.0
