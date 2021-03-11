# DIDKit HTTP

DIDKit exposes its functionality as an HTTP server.

## Build

```sh
$ cargo build
```

## Install
```sh
$ cargo install --path .
```

## CLI

### `didkit-http`

Run a DIDKit HTTP server. The command outputs the URL it is listening on,
and runs until interrupted.

#### Options

- `-s, --host <host>` - Hostname to listen on. Default is `127.0.0.1`.
- `-p, --port <port>` - Port to listen on. Default is a random OS-chosen port.
- `-k, --key <key>`   - Filename of a JWK to use for issuing credentials and
  presentations.
- `-j, --jwk <jwk>`   - JWK to use for issuing credentials and presentations.
- `-r, --did-resolver <url>` - [DID resolver HTTP(S) endpoint][did-resolution-https-binding] URL to use for resolving DIDs and dereferencing DID URLs that the built-in resolver does not support. Equivalent to environmental variable `DID_RESOLVER`.

#### Issuer keys

Provide issuer keys using the `-k`/`--key-path` or `-j`/`--jwk` options. If none are provided, issuance functionality will be unavailable. If one is provided, that one will be used to sign all credentials and presentations, regardless of the proof options in the issuance request. If more than one key is provided, the issuance request may identify which key to use for signing by its DID in the `verificationMethod` property of the proof options; if none is identified in that property, the first key is used.

## Rust library

Rust crate `didkit-http` contains DIDKit's HTTP server implementation as a Rust
library. Struct `didkit_http::DIDKitHTTPMakeSvc` implements a Tower
([hyper](https://hyper.rs/))
[Service](https://docs.rs/tower-service/0.3.0/tower_service/trait.Service.html).

## API

### Verifiable Credentials and Verifiable Presentations

The following routes implement [W3C CCG's VC HTTP API (vc-http-api)][vc-http-api] [v0.0.1][vc-http-api-0.0.1]. POST bodies should be `application/json`. Output will be `application/json` on success; on error it will be either `application/json` or plain text. For more details, see `vc-http-api`.

#### POST `/credentials/issue`

Issue a verifiable credential. The server uses its configured key and the given linked data proof options to generate a proof and append it to the given credential. On success, the resulting verifiable credential is returned, with HTTP status 201.

#### POST `/credentials/verify`

Verify a verifiable credential. The server verifies the given credential with the given linked data proof options. To successfully verify, the credential must contain at least one proof that verifies successfully. Verification results include a list of checks performed, warnings that should be flagged to the user, and errors encountered. On success, the errors list will be empty, and the HTTP status code will be 200.

#### POST `/credentials/prove`

Create a verifiable presentation. Given a presentation and linked data proof options, the server uses its key to generate a proof and append it to the presentation. On success, returns the verifiable presentation and HTTP status 201.

#### POST `/presentations/verify`

Verify a verifiable presentation using the given proof options. Returns a verification result. HTTP status 200 indicates successful verification.

### DIDs (Decentralized Identifiers)

The following route implements the [DID Resolution HTTP(S) Binding][did-http].

#### POST `/identifiers/<uri>`

Resolve a DID to a DID document, or dereference a DID URL to a resource. Parameter `<uri>` is the DID or DID URL to resolve/dereference.

[did-http]: https://w3c-ccg.github.io/did-resolution/#bindings-https
[vc-http-api]: https://w3c-ccg.github.io/vc-http-api/
[vc-http-api-0.0.1]: https://github.com/w3c-ccg/vc-http-api/pull/72
[did-resolution-https-binding]: https://w3c-ccg.github.io/did-resolution/#bindings-https
