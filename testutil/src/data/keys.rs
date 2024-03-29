// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Key material intended only for testing.

/* GENERATED START */

/// Test-only RSA keypair `key`.
#[rustfmt::skip]
pub const KEY1_RSA_KEYPAIR: &[u8] = include_bytes!("keys/key1.rsa.pk8");
/// Test-only RSA public key generated from `key1.rsa.pk8`.
#[rustfmt::skip]
pub const KEY1_RSA_PUBLIC: &[u8] = include_bytes!("keys/key1.rsa.pub.pk8");
/// RSA modulus of `key1.rsa.pk8`.
#[rustfmt::skip]
pub const KEY1_RSA_MOD: &[u8] = include_bytes!("keys/generated/key1.rsa.pub.mod");
/// RSA exponent of `key1.rsa.pk8`.
#[rustfmt::skip]
pub const KEY1_RSA_EXP: &[u8] = include_bytes!("keys/generated/key1.rsa.pub.exp");

/// Test-only RSA keypair `key`.
#[rustfmt::skip]
pub const KEY2_RSA_KEYPAIR: &[u8] = include_bytes!("keys/key2.rsa.pk8");
/// Test-only RSA public key generated from `key2.rsa.pk8`.
#[rustfmt::skip]
pub const KEY2_RSA_PUBLIC: &[u8] = include_bytes!("keys/key2.rsa.pub.pk8");
/// RSA modulus of `key2.rsa.pk8`.
#[rustfmt::skip]
pub const KEY2_RSA_MOD: &[u8] = include_bytes!("keys/generated/key2.rsa.pub.mod");
/// RSA exponent of `key2.rsa.pk8`.
#[rustfmt::skip]
pub const KEY2_RSA_EXP: &[u8] = include_bytes!("keys/generated/key2.rsa.pub.exp");

/// Test-only RSA keypair `key`.
#[rustfmt::skip]
pub const KEY3_RSA_KEYPAIR: &[u8] = include_bytes!("keys/key3.rsa.pk8");
/// Test-only RSA public key generated from `key3.rsa.pk8`.
#[rustfmt::skip]
pub const KEY3_RSA_PUBLIC: &[u8] = include_bytes!("keys/key3.rsa.pub.pk8");
/// RSA modulus of `key3.rsa.pk8`.
#[rustfmt::skip]
pub const KEY3_RSA_MOD: &[u8] = include_bytes!("keys/generated/key3.rsa.pub.mod");
/// RSA exponent of `key3.rsa.pk8`.
#[rustfmt::skip]
pub const KEY3_RSA_EXP: &[u8] = include_bytes!("keys/generated/key3.rsa.pub.exp");

/// Test-only ECDSA keypair `key1.ecdsa-p256.pk8`.
#[rustfmt::skip]
pub const KEY1_ECDSA_P256_KEYPAIR: &[u8] = include_bytes!("keys/key1.ecdsa-p256.pk8");
/// Test-only ECDAS public key generated from `key1.ecdsa-p256.pk8`.
#[rustfmt::skip]
pub const KEY1_ECDSA_P256_PUBLIC: &[u8] = include_bytes!("keys/key1.ecdsa-p256.pub.pk8");
/// X coordinate of `key1.ecdsa-p256.pk8`.
#[rustfmt::skip]
pub const KEY1_ECDSA_P256_X: &[u8; 32] = include_bytes!("keys/generated/key1.ecdsa-p256.pub.x");
/// Y coordinate of `key1.ecdsa-p256.pk8`.
#[rustfmt::skip]
pub const KEY1_ECDSA_P256_Y: &[u8; 32] = include_bytes!("keys/generated/key1.ecdsa-p256.pub.y");
