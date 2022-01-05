![DIDKit header](https://spruceid.dev/assets/images/didkithead-52d41d35622b77d7662965794aa33eff.png)

[![](https://img.shields.io/github/workflow/status/spruceid/didkit/ci)](https://github.com/spruceid/didkit/actions?query=workflow%3Aci+branch%3Amain) [![](https://img.shields.io/badge/Docker-19.03.x-blue)](https://www.docker.com/) [![](https://img.shields.io/badge/Rust-v1.51.0-orange)](https://www.rust-lang.org/) [![](https://img.shields.io/badge/ssi-v0.1-green)](https://www.github.com/spruceid/ssi) [![](https://img.shields.io/badge/License-Apache--2.0-green)](https://github.com/spruceid/didkit/blob/main/LICENSE) [![](https://img.shields.io/twitter/follow/spruceid?label=Follow&style=social)](https://twitter.com/spruceid)

Check out the DIDKit documentation [here](https://spruceid.dev/docs/didkit/).

# DIDKit

DIDKit provides Verifiable Credential and Decentralized Identifier
functionality across different platforms. It was written primarily in Rust due
to Rust's expressive type system, memory safety, simple dependency web, and
suitability across different platforms including embedded systems. DIDKit
embeds the [`ssi`](https://github.com/spruceid/ssi) library, which contains the
core functionality.

![DIDKit core components](https://user-images.githubusercontent.com/37127325/132885609-a5ca8019-e072-47ca-8088-1e278df7b3fe.png)

## Maturity Disclaimer
In the v0.1 release on January 27th, 2021, DIDKit has not yet undergone a
formal security audit and to desired levels of confidence for suitable use in
production systems. This implementation is currently suitable for exploratory
work and experimentation only. We welcome feedback on the usability,
architecture, and security of this implementation and are committed to a
conducting a formal audit with a reputable security firm before the v1.0
release.

We are setting up a process to accept contributions. Please feel free to open
issues or PRs in the interim, but we cannot merge external changes until this
process is in place.

We are also in the process of creating crates.io entries for the DIDKit and SSI
packages.

## Install

### Manual

DIDKit is written in [Rust][]. To get Rust, you can use [Rustup][].

Spruce's [ssi][] library must be cloned alongside the `didkit` repository:
```sh
$ git clone https://github.com/spruceid/ssi ../ssi --recurse-submodules
```

Build DIDKit using [Cargo][]:
```sh
$ cargo build
```
That will give you the DIDKit CLI and HTTP server executables located at
`target/debug/didkit` and `target/debug/didkit-http`, respectively. You can also build and install DIDKit's components separately. Building the FFI libraries will require additional dependencies. See the corresponding readmes linked below for more info.


### Container

Both the CLI and HTTP server are containerised and available under
`ghcr.io/spruceid/didkit-(cli|http)`.

You can use the images like CLIs:
```bash
$ docker run ghcr.io/spruceid/didkit-cli:latest --help
$ docker run --init -p 8080 ghcr.io/spruceid/didkit-http:latest --port 8080
```

> You can pass JWKs either by sharing a volume with `docker run --volume`, or by passing the JWK directly with `docker run -e JWK=$MY_JWK` or `docker run didkit-http --jwk $MY_JWK`.

#### Build Images

The Dockerfiles rely on having `ssi` in the root of `didkit` (a symbolic link will not work unfortunately).

Then the images can be built with:
```bash
$ docker build -f Dockerfile-cli . -t didkit-cli
$ docker build -f Dockerfile-http . -t didkit-http
```

And to use them, replace `ghcr.io/spruceid/didkit-(cli|http):latest` with `didkit-(cli|http)`.

## Usage

DIDKit can be used in any of the following ways:

- [CLI](cli/) - `didkit` command-line program
- [HTTP](http/) - HTTP server (Rust library and CLI program)
- [FFI](lib/FFI.md) - libraries for C, Java, Android, and Dart/Flutter

[Rust]: https://www.rust-lang.org/
[rustup]: https://rustup.rs/
[Cargo]: https://doc.rust-lang.org/cargo/
[ssi]: https://github.com/spruceid/ssi
