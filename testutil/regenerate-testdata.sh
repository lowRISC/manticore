#!/bin/bash
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Regenerates test data for Manticore.

set -e

# Checks that a particular program exists. Usage:
#
# $ check_dep program install_url
function check_dep() {
  if ! command -v $1 &> /dev/null; then
    echo "Could not find required program $1."
    if [[ -n "$2" ]]; then
      echo "You can find it at $2."
    fi
    exit 1
  fi
}

# Clears the generated portion of a Rust file. Usage:
#
# $ clear_rust_file rust_file
function clear_rust_file() {
  perl -pi -e 'last if m#/\* GENERATED START \*/.*#' $1
  echo '/* GENERATED START */' >> "$1"
  echo >> "$1"
}

# Appends a byte array constant to Rust file. Usage:
#
# $ push_const rust_file bin_file const_name comment
function push_const() {
  module="$(dirname "$1")"
  path="$(realpath --relative-to="$module" "$2")"
  
  const="$(tr '.-/' '_' <<< "$3")"

  # xargs will conveniently trim its input!
  comment="$(xargs <<< "$4" | perl -pe 's#^#/// #')"

  cat >> "$1" <<RUST
$comment
#[rustfmt::skip]
pub const ${const^^}: &[u8] = include_bytes!("$path");
RUST
}

check_dep openssl
check_dep ascii2der https://github.com/google/der-ascii

REPO_TOP="$(git rev-parse --show-toplevel)"
DATA_DIR="$REPO_TOP/testutil/src/data"

SCRATCH="$(mktemp /tmp/manticore-der-ascii-hack.XXX)"
trap 'rm -f -- "$SCRATCH"' INT TERM HUP EXIT

## Generate public keys from keypairs.
KEYS_RS="$DATA_DIR/keys.rs"
clear_rust_file "$KEYS_RS"

# RSA keypairs.
rm "$DATA_DIR"/keys/*.rsa.pub.pk8
for key in $(find "$DATA_DIR/keys" -name '*.rsa.pk8' -type f | sort); do
  echo "Processing RSA key $key..." >&2
  base="${key%.rsa.pk8}"
  pub="$base.rsa.pub.pk8"
  openssl rsa \
    -pubout \
    -inform DER -outform DER \
    -in "$key" -out "$pub" \
    2> /dev/null

  push_const \
    "$KEYS_RS" "$key" \
    "$(basename "$base")_RSA_KEYPAIR" \
    "Test-only RSA keypair \`$(basename "$base").rsa.pk8\`."
  push_const \
    "$KEYS_RS" "$pub" \
    "$(basename "$base")_RSA_PUBLIC" \
    "Test-only RSA public key generated from \`$(basename "$base").rsa.pk8\`."
  echo >> "$KEYS_RS"
done

## Generate DER snippets using der-ascii.
DER_RS="$DATA_DIR/der.rs"
clear_rust_file "$DER_RS"

DER_GEN="$DATA_DIR/der/generated"
rm -r "$DER_GEN"
mkdir -p "$DER_GEN"

for der in $(find "$DATA_DIR/der" -name '*.der' -type f | sort); do
  echo "Processing der-ascii file $der..." >&2
  bin="$DER_GEN/$(basename $der).bin"
  ascii2der -i "$der" -o "$bin"

  push_const \
    "$DER_RS" "$bin" \
    "$(basename "${der%.der}")" \
    "DER snippet generated from \`$(basename "$der")\`."
  echo >> "$DER_RS"
done

## Generate X.509 certs using der-ascii.
# Right now we do a gross hack to sign the certs. We can get rid
# of it once https://github.com/google/der-ascii/pull/18 is merged.
#
# There is a separate, similarly gross hack to work around not being
# able to include external blobs, like keys, into der-ascii files.
# This will also be fixed in the above PR.
X509_RS="$DATA_DIR/x509.rs"
clear_rust_file "$X509_RS"

X509_GEN="$DATA_DIR/x509/generated"
# This assumes signing is deterministic for idempotence.
# Once we start doing things with ECDSA, we'll have to do something a bit
# smarter.
rm -r "$X509_GEN"
mkdir -p "$X509_GEN"

for tbs in $(find "$DATA_DIR/x509" -name '*.tbs' -type f | sort); do
  echo "Processing X.509 to-be-signed certificate $tbs..." >&2
  bin="$X509_GEN/$(basename $tbs).bin"

  # First, get the desired signing key, and its associated OID, out of the
  # certificate.
  alg="$(grep '# sign-alg:' "$tbs" | cut -d: -f2)"
  key="$DATA_DIR/$(grep '# sign-key:' "$tbs" | cut -d: -f2)"

  # Next, expand all # include: directives.
  cat "$tbs" > "$SCRATCH"
  for include in $(grep '# include:' "$tbs" | sort -u | cut -d: -f2); do
    included="$DATA_DIR/$include"
    hex_encoded="$(xxd -p "$included" | tr -d '\n')"
    perl -pi -e 's!\Q# include:'"$include"'\E!`'"$hex_encoded"'`!g' "$SCRATCH"
  done

  # Then, sign the to-be-signed portion of the cert.
  # This currently assumes RSA; it may be worth doing a `case` on
  # `$alg`.
  ascii2der -i "$SCRATCH" | openssl dgst \
    -keyform DER \
    -sign "$key" \
    -sha256 \
    -out "$bin"

  # Now, input the contents of the signature into the real cert.
  ascii2der -o "$bin" <<DER
    SEQUENCE {
      $(cat "$SCRATCH")
      $alg
      BIT_STRING {
        \`00\` \`$(
          # Make sure to remove trailing newlines.
          xxd -p "$bin" | tr -d '\n'
        )\`
      }
    }
DER
  push_const \
    "$X509_RS" "$bin" \
    "$(basename "${tbs%.tbs}")" \
    "X509 certificate generated from \`$(basename "$tbs")\`."
  echo >> "$X509_RS"
done

cargo fmt
