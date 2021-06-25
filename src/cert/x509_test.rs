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
    let data = testdata::X509_SELF_SIGNED.as_slice_less_safe();
    let cert =
        Cert::parse(data, CertFormat::RiotX509, None, &mut RingCiphers::new())
            .unwrap();

    assert_eq!(cert.subject(), cert.issuer());
    assert!(cert.supports_cert_signing());
    assert!(cert.is_explicit_ca_cert());
    assert!(!cert.is_within_path_len_constraint(2));
}
