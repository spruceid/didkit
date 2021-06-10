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

## Publishing
### **OBS: After each platform build the folders _`build/`_ and _`didkit.egg-info`_ must be removed, otherwise the previous builds binaries are included in the new wheel.**

Refeer to [cross compile](/CROSS.md) for information on how to build from linux
to other platforms.


```bash
python3 setup.py bdist_wheel -p $PLATFORM
```

Valid values for `$PLATFORM` are the following:
 - `manylinux_GLIBCMAJOR_GLIBCMINOR_ARCH` for linux builds
 - `macosx-10.MACOSX_DEPLOYMENT_TARGET_ARCH` for macOS builds
 - `win-amd64` for Windows builds

`GLIBC` version can be found running `ldd --version` at the shell, `ARCH` can be
found running `uname -a`.

Example publishing from linux for linux:
```bash
ldd --version
ldd (Ubuntu GLIBC 2.31-0ubuntu9.2) 2.31
uname -a
x86_64 x86_64 x86_64 GNU/Linux
python3 setup.py bdist_wheel -p manylinux_2_31-x86_64
```

Example publishing from linux for macOS:
 - `MACOSX_DEPLOYMENT_TARGET=10.10` (this is set when buildng for mac)
```bash
uname -a
x86_64
python3 setup.py bdist_wheel -p macosx.10.10-x86_64
```

Example publishing from linux for Windows:
```bash
python3 setup.py bdist_wheel -p win-amd64
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