---
id: intro
title: Introducing DIDKit
hide_title: true
sidebar_label: Introduction
slug: /didkit/
---

![DIDKit header](/img/didkithead.png)

[![](https://img.shields.io/badge/Docker-19.03.x-blue)](https://www.docker.com/) [![](https://img.shields.io/badge/Rust-v1.49.0-orange)](https://www.rust-lang.org/) [![](https://img.shields.io/badge/ssi-v0.1-green)](https://www.github.com/spruceid/ssi) [![](https://img.shields.io/badge/License-Apache--2.0-green)](https://github.com/spruceid/didkit/blob/main/LICENSE) [![](https://img.shields.io/twitter/follow/sprucesystems?label=Follow&style=social)](https://twitter.com/sprucesystems) 

DIDKit provides Verifiable Credential and Decentralized Identifier
functionality across different platforms. It was written primarily in Rust due
to Rust's expressive type system, memory safety, simple dependency web, and
suitability across different platforms including embedded systems.

It supports the following high level use cases, with more to be added shortly:

- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) with
  JSON-LD Proofs: issuance, presentation, and verification.
- [W3C Decentralized Identifiers](https://www.w3.org/TR/did-core/): resolution
  for did-key, did-web, and one layer of did-tezos.

DIDKit ships with a command line tool and HTTP service. The HTTP service aims
to comply with [HTTP-VC-API](https://w3c-ccg.github.io/vc-http-api/).

Through cross-compilation and linking through C ABIs, DIDKit also supports
other platforms through SDKs for:

- [C/Objective-C](https://github.com/spruceid/didkit/tree/main/lib/cbindings) (C 
ABI)
- [Java](https://github.com/spruceid/didkit/tree/main/lib/java) (via JNI, see an 
[example project using Spring Boot](
https://github.com/spruceid/didkit/tree/example-java/examples/java-springboot))
- [Android](https://github.com/spruceid/didkit/tree/main/lib/android) (via Java)
- [Flutter](https://github.com/spruceid/didkit/tree/main/lib/flutter) (via Android 
and iOS)
- ([WIP](https://github.com/spruceid/didkit/pull/17)) JavaScript/ES6 (npm-linked 
library)
- ([WIP](https://github.com/spruceid/didkit/pull/15)) WASM (cross-compiled using 
[wasm-pack](https://github.com/rustwasm/wasm-pack))
- (Future) PHP, Python, Ruby/Rails, Go, C#, C++

Although support across different platforms is in its early stages, we will
continue to add new platforms and improve interface ergonomics over time. For
platforms that do not currently have SDK support, the HTTP API and command line
tools are readily integrated.

## Quickstart

In this quickstart, we will build and run the command line tool along with the
HTTP server.

Prerequisites:
- GNU/Linux or MacOS, not yet tested on Windows.
- [Rust nightly](https://www.rust-lang.org/tools/install) (`rustup default
  nightly`)

Building `didkit` (we are working on crate packaging):
```sh
$ git clone https://github.com/spruceid/ssi
$ git clone https://github.com/spruceid/didkit
$ cd didkit/
$ cargo build
```

Using `didkit` CLI
([documentation](https://github.com/spruceid/didkit/tree/main/cli)):
```sh
$ ./target/debug/didkit -h
$ ./target/debug/didkit generate-ed25519-key > key.jwk
```

Using `didkit` HTTP server
([documentation](https://github.com/spruceid/didkit/tree/main/http)):
```sh
$ ./target/debug/didkit-http -k key.jwk
Listening on http://127.0.0.1:51467/
```

Please see the installation instructions for more detailed steps or how to use
containerized builds. The CLI and HTTP related pages in the [examples
section](/docs/didkit/examples) will demonstrate how to issue and verify
Verifiable Credentials and Verifiable Presentations.

## Specifications and Test Suites

To demonstrate our commitment to standards and interoperability, we have
ensured that our implementation conforms to the following specifications and
aspire to pass their test suites where applicable:

- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) 
[Test Suite](https://github.com/w3c/vc-test-suite) (passing, 
[instructions](https://github.com/spruceid/ssi/tree/main/vc-test))
- [W3C Decentralized Identifiers](https://www.w3.org/TR/did-core/) 
(test suite pending CR, [syntax support](
https://github.com/spruceid/ssi/blob/main/src/did.pest))
- [VC HTTP API Test Suite v0.0.1](
https://github.com/w3c-ccg/vc-http-api/tree/master/packages/plugfest-2020)
(passing, [instructions](
https://github.com/spruceid/vc-http-api/tree/spruce/packages/plugfest-2020/vendors/spruce))
- [RDF Dataset Normalization Test Cases](
https://json-ld.github.io/normalization/tests/) (passing, [instructions](#))
- [JSON-LD to RDF Transformation Test Cases](
https://w3c.github.io/json-ld-api/tests/toRdf-manifest.html) 
(440/450 passing, [instructions](#))
- [Linked Data Proofs 1.0](https://w3c-ccg.github.io/ld-proofs/)
- [DID Resolution](https://w3c-ccg.github.io/did-resolution/)
- IETF: [JWT](https://tools.ietf.org/html/rfc7519),
  [JWS](https://tools.ietf.org/html/rfc7515),
  [JWK](https://tools.ietf.org/html/rfc7517),
  [JWA](https://tools.ietf.org/html/rfc7518),
  [CFRG ECDH and Signatures in JOSE](https://tools.ietf.org/html/rfc8037) 

## Cryptography Backends

We strongly prefer tried and tested implementations of cryptographic functions
and believe that it's most responsible to list them out in a forthcoming manner
to any potential users. DIDKit is engineered so that the target platform and
compile-time flags may be used to specify different cryptographic backends,
such as to leverage native hardware capabilities, cross-compile to e.g. WASM,
or to give advanced users the option to only use libraries that they trust.

- [`ring`, v0.16](https://docs.rs/ring/0.16.19/ring/): default for hashes, ed25519
  functions, RSA, and randomness. The ed25519 functions here cannot currently
  compile to WASM.
- [`rsa`, v0.3](https://docs.rs/rsa/0.3.0/rsa/): optionally for RSA.
- [`ed25519-dalek`, v1](https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek):
  optionally for ed25519. Compiles to WASM.
- [`rand`, v0.7](https://docs.rs/rand/0.7.3/rand/): optionally for randomness.
- [`sha2`, v0.9](https://docs.rs/sha2/0.9.2/sha2/): optionally for sha256
  hashes.

If you have constructive opinions about the set of cryptographic libraries that
should be supported, please [open an issue](https://github.com/spruceid/ssi).

## Features

The core featureset of DIDKit is expanding steadily over time and in the open,
so feel free to engage with the repository directly on github. Currently,
DIDKit currently supports the following features:

- Key generation and handling.
- Issuance and presentation of W3C Verifiable Credentials in JSON-LD, signed by
  a local and/or passed key.
- Verification of W3C Verifiable Credentials in JSON-LD.

DID Methods supported so far: 
* did-key
* did-web
* did-tezos (tz1 and resolution layer 1)

Proof types verifiable so far:
- RSASignature2018
- Ed25519VerificationKeys

## Roadmap

The following tools and features are high priority for subsequent releases:
1. Exposing interfaces for JWT-based Verifiable Credential workflows
2. JSON-LD context editor
3. Registration of several new LD signature suites and support for new
   cryptography
4. Further DID method support: did-tezos (tz2/tz3 and resolution layers 2 and
   3), did-btcr, did-onion
5. BBS+ signatures
6. DIDComm support
7. Aries interoperability profile support
