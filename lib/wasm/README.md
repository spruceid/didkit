# DIDKit WASM

_**The current version of the `ring` crate does not provide all the symbols
needed to run on the browser, see DEPS.md**_


To install `wasm-pack` run:

```bash
cargo install wasm-pack
```

## ASM target
For the ASM target the `wasm2js` build is necessary, to get this tool
follow the steps in [binaryen](https://github.com/WebAssembly/binaryen#building).

To compile all features for WASM target:
```bash
wasm-pack build --target web
```

To compile all features for ASM target:
```bash
wasm-pack build --target bundler
BINARYEN_ROOT/bin/wasm2js --pedantic -o didkit_wasm_bg1.js didkit_wasm_bg.wasm
./repack.sh
npm install
npm run build
npm run test
```

To compile all features plus `wasm32_c` on `ring`, a C compiler is needed, see
[spruceid/ssi](https://github.com/spruceid/didkit/tree/wasm):

On Ubuntu this one option is to install `clang` and `llvm`:
```bash
sudo apt install clang-10 llvm-10
```

Then to compile with all features:
```bash
TARGET_CC=clang-10 TARGET_AR=llvm-ar-10 wasm-pack build
```

To use a custom subset of features:
```bash
wasm-pack build -- --no-default-features --features=issue        # issue credential/presentation
wasm-pack build -- --no-default-features --features=verify       # verify credential/presentation
wasm-pack build -- --no-default-features --features=credential   # issue/verify credential
wasm-pack build -- --no-default-features --features=presentation # issue/verify presentation
```
*don't forget to add `TARGET_CC` and `TARGET_AR` if using `ring` with `wasm32_c`*
