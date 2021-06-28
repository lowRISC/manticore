// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! X.509 parser tests.
//!
//! These are hung off to the side to avoid cluttering the main x509.rs.

use crate::cert;
use crate::cert::testdata;
use crate::cert::Algo;
use crate::cert::Cert;
use crate::cert::CertFormat;
use crate::cert::PublicKeyParams;
use crate::cert::RingCiphers;
use crate::crypto;
use crate::crypto::ring;
use crate::crypto::rsa::KeyPair as _;
use crate::crypto::sig;

/// A `Ciphers` that blindly accepts all signatures.
#[allow(unused)]
struct NoVerify;
impl sig::Verify for NoVerify {
    type Error = ();
    fn verify(
        &mut self,
        _: &[u8],
        _: &[u8],
    ) -> core::result::Result<(), sig::Error> {
        Ok(())
    }
}
impl cert::Ciphers for NoVerify {
    type Error = ();
    fn verifier<'a>(
        &'a mut self,
        _: Algo,
        _: &PublicKeyParams,
    ) -> Option<&'a mut dyn sig::Verify<Error = ()>> {
        Some(self)
    }
}

#[test]
fn self_signed() {
    let cert = Cert::parse(
        testdata::X509_SELF_SIGNED,
        CertFormat::RiotX509,
        None,
        &mut RingCiphers::new(),
    )
    .unwrap();

    assert_eq!(cert.subject(), cert.issuer());
    assert!(cert.supports_cert_signing());
    assert!(cert.is_explicit_ca_cert());
    assert!(!cert.is_within_path_len_constraint(2));
}

#[test]
fn explicit_key() {
    let keypair =
        ring::rsa::KeyPair::from_pkcs8(crypto::testdata::RSA_2048_PRIV_PKCS8)
            .unwrap();

    let cert = Cert::parse(
        testdata::X509_SUB_SIGNED,
        CertFormat::RiotX509,
        Some(&keypair.public().as_cert_params()),
        &mut RingCiphers::new(),
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
                testdata::$data,
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
    unknown_noncritical: X509_OK_UNKNOWN_NONCRITICAL,
    unknown_default_criticality: X509_OK_UNKNOWN_DEFAULT_CRITICALITY,
    no_ca_without_bc: X509_OK_NO_CA_WITHOUT_BC,
}

// Tests where we merely want to check parsing failed.
table_test! { [is_err]
    missing_version: X509_BAD_MISSING_VERSION,
    wrong_version: X509_BAD_WRONG_VERSION,
    missing_serial: X509_BAD_MISSING_SERIAL,
    serial_too_long: X509_BAD_SERIAL_TOO_LONG,
    missing_sig_alg: X509_BAD_MISSING_SIG_ALG,
    different_sig_alg: X509_BAD_DIFFERENT_SIG_ALG,
    missing_rsa_null: X509_BAD_MISSING_RSA_NULL,
    missing_issuer: X509_BAD_MISSING_ISSUER,
    missing_validity: X509_BAD_MISSING_VALIDTY,
    missing_subject: X509_BAD_MISSING_SUBJECT,
    missing_spki: X509_BAD_MISSING_SPKI,
    missing_spki_rsa_modulus: X509_BAD_MISSING_SPKI_RSA_MODULUS,
    missing_extns: X509_BAD_MISSING_EXTNS,
    unknown_critical: X509_BAD_UNKNOWN_CRITICAL,
    ca_without_cert_sign: X509_BAD_CA_WITHOUT_CERT_SIGN,
    cert_sign_without_bc: X509_BAD_CERT_SIGN_WITHOUT_BC,
    cert_sign_with_other_use: X509_BAD_CERT_SIGN_WITH_OTHER_USE,
}
