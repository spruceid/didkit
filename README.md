![DIDKit header](/img/didkithead.png)

[![](https://img.shields.io/badge/Docker-19.03.x-blue)](https://www.docker.com/) [![](https://img.shields.io/badge/Rust-v1.49.0-orange)](https://www.rust-lang.org/) [![](https://img.shields.io/badge/ssi-v0.1-green)](https://www.github.com/spruceid/ssi) [![](https://img.shields.io/badge/License-Apache--2.0-green)](https://github.com/spruceid/didkit/blob/main/LICENSE) [![](https://img.shields.io/twitter/follow/sprucesystems?label=Follow&style=social)](https://twitter.com/sprucesystems) 

Check out the DIDKit documentation [here](https://spruceid.dev/docs/didkit/).

# DIDKit

DIDKit provides Verifiable Credential and Decentralized Identifier
functionality across different platforms. It was written primarily in Rust due
to Rust's expressive type system, memory safety, simple dependency web, and
suitability across different platforms including embedded systems.

![DIDKit core components](/img/didkit-core-components.png)

## Install

### Container

Both the CLI and HTTP server are containerised and available under
`ghcr.io/spruceid/didkit-(cli|http)`.

The image are private for now, so a [Personal Access Token](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/creating-a-personal-access-token)
is required. Once created you can login like so:
```bash
$ docker login ghcr.io -u USERNAME --password-stdin
```

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

### Manual

DIDKit is written in [Rust][]. To get Rust, you can use [Rustup][].

We depend on some Rust nightly features. When installing with Rustup, pick the nightly release channel. Or run `rustup default nightly` to switch to it.
([More info][installing-rust])

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

## Usage

DIDKit can be used in any of the following ways:

- [CLI](cli/) - `didkit` command-line program
- [HTTP](http/) - HTTP server (Rust library and CLI program)
- [FFI](lib/FFI.md) - libraries for C, Java, Android, and Dart/Flutter

[Rust]: https://www.rust-lang.org/
[rustup]: https://rustup.rs/
[Cargo]: https://doc.rust-lang.org/cargo/
[ssi]: https://github.com/spruceid/ssi
[installing-rust]: https://doc.rust-lang.org/nightly/edition-guide/rust-2018/rustup-for-managing-rust-versions.html
