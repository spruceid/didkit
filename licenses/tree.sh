#!/bin/sh
cargo tree -f '{p} {r} {l}' -e normal --target all --prefix none --no-dedupe --manifest-path "$@"
