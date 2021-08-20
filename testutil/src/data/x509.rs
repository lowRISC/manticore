// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Potentially invalid X.509 certificates, both for testing the parser
//! and for use with end-to-end tests.

/* GENERATED START */

/// X509 certificate generated from `bad_ca_without_cert_sign.tbs`.
#[rustfmt::skip]
pub const BAD_CA_WITHOUT_CERT_SIGN: &[u8] = include_bytes!("x509/generated/bad_ca_without_cert_sign.tbs.bin");

/// X509 certificate generated from `bad_cert_sign_with_other_use.tbs`.
#[rustfmt::skip]
pub const BAD_CERT_SIGN_WITH_OTHER_USE: &[u8] = include_bytes!("x509/generated/bad_cert_sign_with_other_use.tbs.bin");

/// X509 certificate generated from `bad_cert_sign_without_bc.tbs`.
#[rustfmt::skip]
pub const BAD_CERT_SIGN_WITHOUT_BC: &[u8] = include_bytes!("x509/generated/bad_cert_sign_without_bc.tbs.bin");

/// X509 certificate generated from `bad_different_sig_alg.tbs`.
#[rustfmt::skip]
pub const BAD_DIFFERENT_SIG_ALG: &[u8] = include_bytes!("x509/generated/bad_different_sig_alg.tbs.bin");

/// X509 certificate generated from `bad_missing_extns.tbs`.
#[rustfmt::skip]
pub const BAD_MISSING_EXTNS: &[u8] = include_bytes!("x509/generated/bad_missing_extns.tbs.bin");

/// X509 certificate generated from `bad_missing_issuer.tbs`.
#[rustfmt::skip]
pub const BAD_MISSING_ISSUER: &[u8] = include_bytes!("x509/generated/bad_missing_issuer.tbs.bin");

/// X509 certificate generated from `bad_missing_rsa_null.tbs`.
#[rustfmt::skip]
pub const BAD_MISSING_RSA_NULL: &[u8] = include_bytes!("x509/generated/bad_missing_rsa_null.tbs.bin");

/// X509 certificate generated from `bad_missing_serial.tbs`.
#[rustfmt::skip]
pub const BAD_MISSING_SERIAL: &[u8] = include_bytes!("x509/generated/bad_missing_serial.tbs.bin");

/// X509 certificate generated from `bad_missing_sig_alg.tbs`.
#[rustfmt::skip]
pub const BAD_MISSING_SIG_ALG: &[u8] = include_bytes!("x509/generated/bad_missing_sig_alg.tbs.bin");

/// X509 certificate generated from `bad_missing_spki_rsa_modulus.tbs`.
#[rustfmt::skip]
pub const BAD_MISSING_SPKI_RSA_MODULUS: &[u8] = include_bytes!("x509/generated/bad_missing_spki_rsa_modulus.tbs.bin");

/// X509 certificate generated from `bad_missing_spki.tbs`.
#[rustfmt::skip]
pub const BAD_MISSING_SPKI: &[u8] = include_bytes!("x509/generated/bad_missing_spki.tbs.bin");

/// X509 certificate generated from `bad_missing_subject.tbs`.
#[rustfmt::skip]
pub const BAD_MISSING_SUBJECT: &[u8] = include_bytes!("x509/generated/bad_missing_subject.tbs.bin");

/// X509 certificate generated from `bad_missing_validty.tbs`.
#[rustfmt::skip]
pub const BAD_MISSING_VALIDTY: &[u8] = include_bytes!("x509/generated/bad_missing_validty.tbs.bin");

/// X509 certificate generated from `bad_missing_version.tbs`.
#[rustfmt::skip]
pub const BAD_MISSING_VERSION: &[u8] = include_bytes!("x509/generated/bad_missing_version.tbs.bin");

/// X509 certificate generated from `bad_serial_too_long.tbs`.
#[rustfmt::skip]
pub const BAD_SERIAL_TOO_LONG: &[u8] = include_bytes!("x509/generated/bad_serial_too_long.tbs.bin");

/// X509 certificate generated from `bad_unknown_critical.tbs`.
#[rustfmt::skip]
pub const BAD_UNKNOWN_CRITICAL: &[u8] = include_bytes!("x509/generated/bad_unknown_critical.tbs.bin");

/// X509 certificate generated from `bad_wrong_version.tbs`.
#[rustfmt::skip]
pub const BAD_WRONG_VERSION: &[u8] = include_bytes!("x509/generated/bad_wrong_version.tbs.bin");

/// X509 certificate generated from `chain1.tbs`.
#[rustfmt::skip]
pub const CHAIN1: &[u8] = include_bytes!("x509/generated/chain1.tbs.bin");

/// X509 certificate generated from `chain2.tbs`.
#[rustfmt::skip]
pub const CHAIN2: &[u8] = include_bytes!("x509/generated/chain2.tbs.bin");

/// X509 certificate generated from `chain3.tbs`.
#[rustfmt::skip]
pub const CHAIN3: &[u8] = include_bytes!("x509/generated/chain3.tbs.bin");

/// X509 certificate generated from `ok_no_ca_without_bc.tbs`.
#[rustfmt::skip]
pub const OK_NO_CA_WITHOUT_BC: &[u8] = include_bytes!("x509/generated/ok_no_ca_without_bc.tbs.bin");

/// X509 certificate generated from `ok_unknown_default_criticality.tbs`.
#[rustfmt::skip]
pub const OK_UNKNOWN_DEFAULT_CRITICALITY: &[u8] = include_bytes!("x509/generated/ok_unknown_default_criticality.tbs.bin");

/// X509 certificate generated from `ok_unknown_noncritical.tbs`.
#[rustfmt::skip]
pub const OK_UNKNOWN_NONCRITICAL: &[u8] = include_bytes!("x509/generated/ok_unknown_noncritical.tbs.bin");

/// X509 certificate generated from `self_signed.tbs`.
#[rustfmt::skip]
pub const SELF_SIGNED: &[u8] = include_bytes!("x509/generated/self_signed.tbs.bin");

/// X509 certificate generated from `sub_signed.tbs`.
#[rustfmt::skip]
pub const SUB_SIGNED: &[u8] = include_bytes!("x509/generated/sub_signed.tbs.bin");
