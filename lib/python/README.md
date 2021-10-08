Check out the DIDKit documentation [here](https://spruceid.dev/docs/didkit/).

# DIDKit Python

DIDKit provides Verifiable Credential and Decentralized Identifier
functionality across different platforms. It was written primarily in Rust due
to Rust's expressive type system, memory safety, simple dependency web, and
suitability across different platforms including embedded systems. DIDKit
embeds the [`ssi`](https://github.com/spruceid/ssi) library, which contains the
core functionality.

![DIDKit core components](https://spruceid.dev/assets/images/didkit-core-components-7abba2778ffe8dde24997f305e706bd8.png)

## Installation and Usage

> TBD PyPI link

## Build from Source

```bash
$ maturin build
```
> You can install `maturin` with `pip install maturin`.

Now the `wheel` should be in the [target directory](../../target/wheel).

## Development

When adding a function or changing the signature of an existing one, make sure
to reflect the changes in [the stub file](./pydidkit.pyi). This is important for
static analysis and IDE support. (This will be automated in the future.)

## Test

Go to [the test directory](./pydidkit_tests/).

## Maturity Disclaimer

Please note: this readme documents an early-stage open-source product ported
manually to python, and we are still incorporating feedback from our first
comprehensive third-party code audit. These artefacts are presented as
functional "betas" for experimentation and to show the direction of the
project (inviting proposals for changes of direction, even!). They are not,
 however, intended for transacting real-world business yet.
