Check out the DIDKit documentation [here](https://spruceid.dev/docs/didkit/).

# DIDKit

DIDKit provides Verifiable Credential and Decentralized Identifier
functionality across different platforms. It was written primarily in Rust due
to Rust's expressive type system, memory safety, simple dependency web, and
suitability across different platforms including embedded systems. DIDKit
embeds the [`ssi`](https://github.com/spruceid/ssi) library, which contains the
core functionality.

![DIDKit core components](https://spruceid.dev/assets/images/didkit-core-components-7abba2778ffe8dde24997f305e706bd8.png)

## Building

Make sure you have the latest versions of pip and PyPA’s build installed:
```bash
sudo apt install -y python3-pip python3-virtualenv
python3 -m pip install --upgrade pip build
```

Build DIDKit:
```bash
cargo build --release
```

Build the package
```bash
python3 -m build
```

Install the package
```bash
python3 -m pip install dist/didkit-`cat setup.cfg | grep version | cut -d' ' -f3`-*.whl
```

## Maturity Disclaimer

Please note: this readme documents an early-stage open-source product ported 
manually to python, and we are still incorporating feedback from our first 
comprehensive third-party code audit. These artefacts are presented as 
functional "betas" for experimentation and to show the direction of the 
project (inviting proposals for changes of direction, even!). They are not,
 however, intended for transacting real-world business yet.
