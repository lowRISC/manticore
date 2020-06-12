// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Test-only data..
//!
//! This module includes pre-generated private key material for testing use
//! only. In particular, we keep the private key around to make it possible to
//! re-sign test data to reduce the brittleness of tests.

/// A plaintext string.
pub const PLAIN_TEXT: &[u8] = include_bytes!("plain.txt");

/// The SHA-256 hash of `PLAIN_TEXT`.
pub const PLAIN_SHA256: &[u8] = include_bytes!("plain_sha256.bin");

/// A 2048-bit modulus RSA private key, in PKCS#8 format.
///
/// Signatures may be created using this key and the following `openssl` call:
/// ```text
/// openssl dgst -sha256 -keyform DER \
///   -sign rsa_2048_private_key.pk8 \
///   -out my_signature.pk1 \
///   plain.txt
/// ```
pub const RSA_2048_PRIV_PKCS8: &[u8] =
    include_bytes!("rsa_2048_private_key.pk8");

/// An RSA signature for `PLAIN_TEXT`, using `RSA_2048_PRIV_PKCS8` as the
/// signing key.
///
/// The signature is in PKCS v1.5 format.
pub const RSA_2048_SHA256_SIG_PKCS1: &[u8] =
    include_bytes!("rsa_2048_sha256_sig.pk1");
