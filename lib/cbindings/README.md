# cbindings for didkit

This crate builds a C header file for the didkit crate. It is a separate crate so that it runs after the didkit crate is built, rather than blocking compilation of the didkit crate. If there are syntax errors, the Rust compiler gives more useful output than would the failing build script using cbindgen.

Related issue: [Cargo post-build script execution](https://github.com/rust-lang/cargo/issues/545)
