// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Key material intended only for testing.

/* GENERATED START */

/// Test-only RSA keypair `key1.rsa.pk8`.
#[rustfmt::skip]
pub const KEY1_RSA_KEYPAIR: &[u8] = include_bytes!("keys/key1.rsa.pk8");
/// Test-only RSA public key generated from `key1.rsa.pk8`.
#[rustfmt::skip]
pub const KEY1_RSA_PUBLIC: &[u8] = include_bytes!("keys/key1.rsa.pub.pk8");

/// Test-only RSA keypair `key2.rsa.pk8`.
#[rustfmt::skip]
pub const KEY2_RSA_KEYPAIR: &[u8] = include_bytes!("keys/key2.rsa.pk8");
/// Test-only RSA public key generated from `key2.rsa.pk8`.
#[rustfmt::skip]
pub const KEY2_RSA_PUBLIC: &[u8] = include_bytes!("keys/key2.rsa.pub.pk8");
