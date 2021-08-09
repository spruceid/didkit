#!/bin/sh
set -e
cd "$(dirname "$0")"
./tree.sh ../../rust/library/std/Cargo.toml | sed 's/(.*) //' | sort -u > std.tree
