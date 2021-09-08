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
  ty="$4"

  # xargs will conveniently trim its input!
  comment="$(xargs <<< "$5" | perl -pe 's#^#/// #')"

  cat >> "$1" <<RUST
$comment
#[rustfmt::skip]
pub const ${const^^}: $ty = include_bytes!("$path");
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

KEYS_GEN="$DATA_DIR/keys/generated"
rm -r "$KEYS_GEN"
mkdir -p "$KEYS_GEN"

# RSA keypairs.
# To generate a new *private* key, use
#   openssl genrsa -outform der -out <name>.rsa.pk8 <bits>
rm -f "$DATA_DIR"/keys/*.rsa.pub.pk8
for key in $(find "$DATA_DIR/keys" -name '*.rsa.pk8' -type f | sort); do
  echo "Processing RSA key $key..." >&2
  base="${key%.rsa.pk8}"
  pub="$base.rsa.pub.pk8"
  openssl rsa \
    -pubout \
    -inform DER -outform DER \
    -in "$key" -out "$pub" \
    2> /dev/null

  # Pull out the modulus and exponent. Openssl's commands for this are
  # awful so we abuse der-ascii instead.
  ascii="$(der2ascii < "$pub")"
  mod_ascii="$(grep INTEGER <<< "$ascii" | head -n1)"
  exp_ascii="$(grep INTEGER <<< "$ascii" | tail -n1)"

  mod="$KEYS_GEN/$(basename "$base").rsa.pub.mod"
  exp="$KEYS_GEN/$(basename "$base").rsa.pub.exp"
  unwrap_int='s/INTEGER\s*{\s*(`?)(00)?(\w+)(`?)\s*}/$1$3$4/'
  perl -pe "$unwrap_int" <<< "$mod_ascii" | ascii2der > "$mod"
  perl -pe "$unwrap_int" <<< "$exp_ascii" | ascii2der > "$exp"

  push_const \
    "$KEYS_RS" "$key" \
    "$(basename "$base")_RSA_KEYPAIR" '&[u8]' \
    "Test-only RSA keypair \`$(basename "key")\`."
  push_const \
    "$KEYS_RS" "$pub" \
    "$(basename "$base")_RSA_PUBLIC" '&[u8]' \
    "Test-only RSA public key generated from \`$(basename "$key")\`."
  push_const \
    "$KEYS_RS" "$mod" \
    "$(basename "$base")_RSA_MOD" '&[u8]' \
    "RSA modulus of \`$(basename "$key")\`."
  push_const \
    "$KEYS_RS" "$exp" \
    "$(basename "$base")_RSA_EXP" '&[u8]' \
    "RSA exponent of \`$(basename "$key")\`."
  echo >> "$KEYS_RS"
done

# ECDSA keypairs.
# To generate a new *private* key, use
#   openssl ecparam -name <curve> -genkey -noout -outform der | \
#   openssl pkcs8 -topk8 -nocrypt -outform der -out <name>.ecdsa-<curve>.pk8
rm -f "$DATA_DIR"/keys/*.ecdsa-*.pub.pk8
for key in $(find "$DATA_DIR/keys" -name '*.ecdsa-*.pk8' -type f | sort); do
  echo "Processing ECDSA key $key..." >&2
  base="${key%.ecdsa-*.pk8}"
  curve="${key%.pk8}"
  curve="${curve#"$base.ecdsa-"}"
  pub="$base.ecdsa-$curve.pub.pk8"
  openssl pkcs8 \
    -nocrypt \
    -inform der -outform der \
    -in "$key" | \
  openssl ec \
    -pubout \
    -inform der -outform der \
    -out "$pub" \
    2> /dev/null

  x="$KEYS_GEN/$(basename "$base").ecdsa-$curve.pub.x"
  y="$KEYS_GEN/$(basename "$base").ecdsa-$curve.pub.y"

  unwrap_bits='s/\s*BIT_STRING\s*{\s*`00`\s*`04(\w+)`\s*}/$1/'
  xy="$(der2ascii < "$pub" | grep BIT_STRING | perl -pe "$unwrap_bits")"
  coord_len_hex=$((${#xy} / 2))
  head -c $coord_len_hex <<< $xy | xxd -r -p > "$x"
  tail -c $(($coord_len_hex + 1)) <<< $xy | xxd -r -p > "$y"

  push_const \
    "$KEYS_RS" "$key" \
    "$(basename "$base")_ECDSA_${curve}_KEYPAIR" '&[u8]' \
    "Test-only ECDSA keypair \`$(basename "$key")\`."
  push_const \
    "$KEYS_RS" "$pub" \
    "$(basename "$base")_ECDSA_${curve}_PUBLIC" '&[u8]' \
    "Test-only ECDAS public key generated from \`$(basename "$key")\`."
  push_const \
    "$KEYS_RS" "$x" \
    "$(basename "$base")_ECDSA_${curve}_X" "&[u8; $(($coord_len_hex / 2))]" \
    "X coordinate of \`$(basename "$key")\`."
  push_const \
    "$KEYS_RS" "$y" \
    "$(basename "$base")_ECDSA_${curve}_Y" "&[u8; $(($coord_len_hex / 2))]" \
    "Y coordinate of \`$(basename "$key")\`."
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
    "$(basename "${der%.der}")" '&[u8]' \
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
    "$(basename "${tbs%.tbs}")" '&[u8]' \
    "X509 certificate generated from \`$(basename "$tbs")\`."
  echo >> "$X509_RS"
done

cd "$(dirname "$0")"
cargo fmt
