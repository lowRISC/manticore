// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! X.509 parser tests.
//!
//! These are hung off to the side to avoid cluttering the main x509.rs.

use testutil::data;
use testutil::data::keys;

use crate::cert::Cert;
use crate::cert::CertFormat;
use crate::crypto::ring;
use crate::crypto::rsa::KeyPair as _;
use crate::crypto::sig::NoVerify;

#[test]
#[cfg_attr(miri, ignore)]
fn self_signed() {
    let cert = Cert::parse(
        data::x509::SELF_SIGNED,
        CertFormat::RiotX509,
        None,
        &mut ring::sig::Ciphers::new(),
    )
    .unwrap();

    assert_eq!(cert.subject(), cert.issuer());
    assert!(cert.supports_cert_signing());
    assert!(cert.is_explicit_ca_cert());
    assert!(!cert.is_within_path_len_constraint(2));
}

#[test]
#[cfg_attr(miri, ignore)]
fn explicit_key() {
    let keypair =
        ring::rsa::KeyPair::from_pkcs8(keys::KEY1_RSA_KEYPAIR).unwrap();

    let cert = Cert::parse(
        data::x509::SUB_SIGNED,
        CertFormat::RiotX509,
        Some(&keypair.public().as_cert_params()),
        &mut ring::sig::Ciphers::new(),
    )
    .unwrap();

    assert_eq!(cert.subject(), cert.issuer());
    assert!(cert.supports_cert_signing());
    assert!(cert.is_explicit_ca_cert());
    assert!(!cert.is_within_path_len_constraint(2));
}

macro_rules! table_test {
    ([$pred:ident] $($test:ident:$data:ident,)*) => {$(
        #[test]
        fn $test() {
            let cert = Cert::parse(
                data::x509::$data,
                CertFormat::RiotX509,
                None,
                &mut NoVerify,
            );
            assert!(cert.$pred());
        }
    )*}
}

// Tests where we merely want to check parsing succeeded.
table_test! { [is_ok]
    unknown_noncritical: OK_UNKNOWN_NONCRITICAL,
    unknown_default_criticality: OK_UNKNOWN_DEFAULT_CRITICALITY,
    no_ca_without_bc: OK_NO_CA_WITHOUT_BC,
}

// Tests where we merely want to check parsing failed.
table_test! { [is_err]
    missing_version: BAD_MISSING_VERSION,
    wrong_version: BAD_WRONG_VERSION,
    missing_serial: BAD_MISSING_SERIAL,
    serial_too_long: BAD_SERIAL_TOO_LONG,
    missing_sig_alg: BAD_MISSING_SIG_ALG,
    different_sig_alg: BAD_DIFFERENT_SIG_ALG,
    missing_rsa_null: BAD_MISSING_RSA_NULL,
    missing_issuer: BAD_MISSING_ISSUER,
    missing_validity: BAD_MISSING_VALIDTY,
    missing_subject: BAD_MISSING_SUBJECT,
    missing_spki: BAD_MISSING_SPKI,
    missing_spki_rsa_modulus: BAD_MISSING_SPKI_RSA_MODULUS,
    missing_extns: BAD_MISSING_EXTNS,
    unknown_critical: BAD_UNKNOWN_CRITICAL,
    ca_without_cert_sign: BAD_CA_WITHOUT_CERT_SIGN,
    cert_sign_without_bc: BAD_CERT_SIGN_WITHOUT_BC,
    cert_sign_with_other_use: BAD_CERT_SIGN_WITH_OTHER_USE,
}
