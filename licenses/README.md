# DIDKit Licenses

This crate produces a report showing the software and document packages and
licenses used by DIDKit and its dependencies. This report is intended for
informational purposes, and to assist compliance with license terms that
require distribution of covered software and/or documents to include the
license text, attribution, copyright notices, and/or other notices.

## Usage

Building this package produces a text file containing the license and packages
info: `licenses.txt`. This file can then be included in binary distributions of
DIDKit, i.e. as a file in a tarball alongside the binary executable/library,
and/or as an output of an interactive command or screen as part of the
distributed program.

When making a binary build of DIDKit for distribution, 

## Updating

This package builds a license report using two input files from this directory:
`std.tree` and `didkit.tree`.

### DIDKit dependencies: `didkit.tree`

`didkit.tree` in this directory contains info about DIDKit's crate dependency
tree.

Run `./tree-didkit.sh` from this directory to build the `didkit.tree` file.

`didkit.tree` it is not checked into this repo, as it is expected to change often.

### Standard library dependencies: `std.tree`

`std.tree` in this directory contains info about the crate dependency tree of
the Rust runtime.

Run `./tree-std.sh` from this directory to rebuild the `std.tree` file.

`std.tree` is checked into this repo as it is expected to change relatively
slowly.

Rebuilding `std.tree` requires the [Rust](https://github.com/rust-lang/rust/)
repo cloned alongside DIDKit's repo, i.e. at `../../rust` relative to this
directory.

### Licenses

This package matches license identifiers against known license SPDX identifiers.
The license identifiers are mapped to license text files, e.g. in the `text/` directory. Some manual overrides are done in `build.rs`, e.g. for specific crates that do not have a license field in their package metadata.

## Updating 

Before publishing a new binary release, run `./tree-didkit.sh` in this
directory to rebuild `didkit.tree`. Then build `licenses.txt` using `cargo
build` (`cargo build -p didkit-licenses` from the repo root).

`std.tree` in this directory should be updated (using `./tree-std.sh`) to
correspond to the Rust compiler/runtime version used to build DIDKit.

If this package's build script encounters new license strings, it will fail,
and `build.rs` must then be updated to handle those license strings.
