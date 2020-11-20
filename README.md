# DIDKit

## Install

DIDKit is written in [Rust][]. To get Rust, you can use [Rustup][].

We depend on some Rust nightly features. When installing with Rustup, pick the nightly release channel. Or run `rustup default nightly` to switch to it.
([More info][installing-rust])

Spruce's [ssi][] library must be cloned alongside the `didkit` repository:
```sh
$ git clone https://github.com/spruceid/ssi ../ssi
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
