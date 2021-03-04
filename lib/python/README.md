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