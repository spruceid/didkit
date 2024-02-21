#!/bin/sh
set -e
cd "$(dirname "$0")"
./tree.sh ../http/Cargo.toml | sed 's/(.*) //' | sort -u > didkit.tree
