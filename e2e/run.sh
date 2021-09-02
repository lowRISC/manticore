#!/bin/bash
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Run Manticore's e2e tests. See the README.md for more details.
set -e

# First, build the e2e binary itself, which acts as the server.
#
# --message-format=json is stable, and prints out newline-separated
# JSON blobs that describe each cargo action. The action that outputs
# the built binary will contain a `"executable":"<path>"` entry.
export MANTICORE_E2E_TARGET_BINARY="$(
  set -e
  cargo build -p e2e --message-format=json \
    | tr '\n' ' ' \
    | perl -pe 's/^.+"executable":"(.+?)".+$/$1/g'
)"

# Now run the tests!
# We forward the script arguments directly to the harness, to allow
# for filtering. RUST_LOG=info can be used to enable log output.
cargo test -p e2e -- $@
