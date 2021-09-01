# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Fixed
- Improve .Jar file, swift wrapper, and gradle build process.
- Add ssh-agent flag to CLI.
- Improve P-256 signing.
- Use Default with LinkedDataProofOptions.
- Rename functions on Python package.
- Improve iOS build process
- Improve TypeScript support in Node.js package

### Added
- work-in-progress implementation of [ZCapLD][] in WASM.
- updated SSI verification to include resolution step where necessary.
- maven and cocoapods packaging.
- added SSH public key-to-DID method.
- Enable `did:webkey`.
- Issue and verify JWT VCs and VPs.
- Add JWKFromTezos function in WASM

## [0.2.1] - 2021-04-13
### Fixed
- Include readme and license files in `didkit` crate.

## [0.2.0] - 2021-04-12
### Added
- Add Node.js package, using [Neon][].
- Add WASM package, using [wasm-pack][].
- Add ASM.js package, using [Binaryen][].
- Add Python package.
- Add [Svelte][] [CHAPI][] wallet example.
- Add Java [Spring Boot][] example.
- Add [JavaServer Pages (JSP)][jsp] example.
- Add [Django][] example.
- Add [Flask][] example.
- Add Resolve DID command.
- Add Dereference DID URL command.
- Add DIDAuth command.
- Add fallback resolver option for CLI and HTTP server.
- Allow using multiple DID methods in `example.sh`.
- Support Rust stable.
- Support iOS, with static library and Flutter plugin.
- Enable `did:web`.
- Enable `did:sol`.
- Enable `did:onion`.
- Enable `did:pkh`.
- Enable `P-256` curve.
- Enable HTTP(S) in WASM, for parity with other platforms.
- Enable external signing for WASM.
- Add test driver for [vc-http-api-test-server][] (`vc-http-api v0.0.2`).
- Public GCHR container images.

### Changed
- Use Flutter `dev` channel.
- Update `async-std` dependency version.
- Use [Tokio][] runtime.
- Use `vc-http-api` controller pattern routes.
- Update [`ssi` since `v0.1.0`][ssi-0.2.0-pre]
- Change method name to method pattern for `key-to-did`/`keyToDID` and `key-to-verification-method`/`keyToVerificationMethod`.

### Fixed
- Fixed optionality of `ssi` features.
- Enable `http2`, to fix build.
- Improve `PATH` quoting, for Windows.

### Security
- Update `node-notifier` dev dependency.

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

[Binaryen]: https://github.com/WebAssembly/binaryen#building
[CHAPI]: https://w3c-ccg.github.io/credential-handler-api/
[Django]: https://www.djangoproject.com/
[Flask]: https://palletsprojects.com/p/flask/
[Initial release]: https://sprucesystems.medium.com/didkit-v0-1-is-live-d0ea6638dbc9
[Neon]: https://www.neon-bindings.com
[Spring Boot]: https://spring.io/projects/spring-boot
[Svelte]: https://svelte.dev/
[Tokio]: https://tokio.rs/
[Verifiable Presentations]: https://w3c.github.io/vc-data-model/#presentations-0
[did:key]: https://w3c-ccg.github.io/did-method-key/
[did:tz]: https://did-tezos-draft.spruceid.com/
[did:web]: https://w3c-ccg.github.io/did-method-web/
[jsp]: https://www.oracle.com/java/technologies/jspt.html
[ssi-0.2.0-pre]: https://github.com/spruceid/ssi/compare/v0.1.0...1ecb3d90a0fdd06a4ae3b34064a908918b51a230
[vc-data-model]: https://w3c.github.io/vc-data-model/
[vc-http-api-0.1.1]: https://w3c-ccg.github.io/vc-http-api/versions/v0.0.1/
[vc-http-api-test-server]: https://github.com/w3c-ccg/vc-http-api/tree/b4df10d/packages/vc-http-api-test-server
[wasm-pack]: https://rustwasm.github.io/wasm-pack/
[zcap-ld]: https://w3c-ccg.github.io/zcap-ld/

[Unreleased]: https://github.com/spruceid/didkit/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/spruceid/didkit/releases/tag/v0.2.1
[0.2.0]: https://github.com/spruceid/didkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/spruceid/didkit/releases/tag/v0.1.0
