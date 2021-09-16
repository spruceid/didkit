[![](https://img.shields.io/npm/v/@spruceid/didkit-wasm?label=%40spruceid%2Fdidkit-wasm&logo=npm)](https://www.npmjs.com/package/@spruceid/didkit-wasm) [![](https://img.shields.io/npm/v/@spruceid/didkit-wasm-node?label=%40spruceid%2Fdidkit-wasm-node&logo=npm)](https://www.npmjs.com/package/@spruceid/didkit-wasm-node)
<!-- Might want those badge in the main README. -->

# DIDKit WASM

## Prerequisites to Build from Source

NPM packages are available but if you would like to compile DIDKit yourself
(e.g. to enable different cryptographic backends) you will need the WASM
compiler toolchain as well as a specific build tool:

```bash
$ rustup target add wasm32-unknown-unknown
$ cargo install wasm-pack
# OR
# $ curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

## Installation and Usage

### Node

WASM can be used in Node.js (any recent version):
```bash
$ npm i @spruceid/didkit-wasm-node
```

Or build it from source:
```bash
$ wasm-pack build --target nodejs
```

### Web Frameworks (Bundled)

WASM can be used with web frameworks and bundlers like Webpack:
```bash
$ npm i @spruceid/didkit-wasm
```

Or build it from source:
```bash
$ wasm-pack build
```

> If Webpack doesn't work with the default configuration, you can have a look at
> our configuration for
> [tzprofiles](https://github.com/spruceid/tzprofiles/blob/main/dapp/webpack.config.js).

### Vanilla Javascript

WASM can be used with plain Javascript with newer browsers. As it cannot be used
as a NPM package you have to build it manually:
```bash
$ wasm-pack build --target web
```

The manual tests in `test/` serve as an example on how to import DIDKit.

## Tests

The `test/` directory contains manual tests to run in the browser. Instructions
are in the README of the directory.

## Non-Default Compilation

_**The current version of the `ring` crate does not provide all the symbols
needed to run on the browser, see DEPS.md**_

To compile all features plus `wasm32_c` on `ring`, a C compiler is needed, see
[spruceid/ssi](https://github.com/spruceid/didkit/tree/wasm):

On Ubuntu this one option is to install `clang` and `llvm`:
```bash
sudo apt install clang-10 llvm-10
```

Then to compile with all features:
```bash
TARGET_CC=clang-10 TARGET_AR=llvm-ar-10 wasm-pack build --out-dir pkg
```

To use a custom subset of features:
```bash
wasm-pack build --out-dir pkg -- --no-default-features --features=issue        # issue credential/presentation
wasm-pack build --out-dir pkg -- --no-default-features --features=verify       # verify credential/presentation
wasm-pack build --out-dir pkg -- --no-default-features --features=credential   # issue/verify credential
wasm-pack build --out-dir pkg -- --no-default-features --features=presentation # issue/verify presentation
```
*don't forget to add `TARGET_CC` and `TARGET_AR` if using `ring` with `wasm32_c`*
