// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! CWT parser tests.
//!
//! These are hung off to the side to avoid cluttering the main cwt.rs.

use testutil::data::keys;

use crate::cert::Cert;
use crate::cert::CertFormat;
use crate::crypto::ring;
use crate::crypto::sig::PublicKeyParams;
use crate::crypto::sig::Sign as _;

const UINT: u8 = 0;
const NINT: u8 = 1;
const UTF8: u8 = 3;
const BYTES: u8 = 2;
const ARRAY: u8 = 4;
const MAP: u8 = 5;

/// Generator for a test CWT.
pub struct TestCwt {
    pub issuer: &'static str,
    pub subject: &'static str,
    pub spki: PublicKeyParams<'static>,
    pub key_usage: &'static [u8],
    pub issuer_key: &'static [u8],
}

impl TestCwt {
    pub fn encode(&self) -> Vec<u8> {
        let protected = raw_cbor!(MAP [
            // Algorithm, i.e., RSA.
            UINT:1  NINT:256,
            // Criticalities.
            UINT:2  ARRAY[UINT:1, UINT:2],
        ]);

        let spki = match &self.spki {
            PublicKeyParams::Rsa { modulus, exponent } => raw_cbor!(MAP [
                // Key type, RSA.
                UINT:1  UINT:3,
                // Algorithm, RSA.
                UINT:3  NINT:256,
                // Modulus.
                NINT:0  BYTES {modulus},
                // Exponent.
                NINT:1  BYTES {exponent},
            ]),
            _ => unimplemented!(),
        };

        let payload = raw_cbor!(MAP [
            // Issuer.
            UINT:1          UTF8 {(self.issuer)},
            // Subject.
            UINT:2          UTF8 {(self.subject)},
            // DICE SPKI.
            NINT:4670551    spki,
            // DICE KeyUsage
            NINT:4670552    BYTES {(self.key_usage)},
        ]);

        let tbs = raw_cbor!(ARRAY [
            UTF8 {"Signature1"},
            BYTES {protected},
            BYTES {},
            BYTES {payload},
        ]);

        let (_, mut signer) = ring::rsa::from_keypair(self.issuer_key);
        let mut sig = vec![0; signer.sig_bytes()];
        let sig_len = signer.sign(&[&tbs], &mut sig).unwrap();

        raw_cbor! {
            BYTES {protected}
            MAP []  // No unprotected fields.
            BYTES {payload}
            BYTES {(sig[..sig_len])}
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn self_signed() {
    let cwt = TestCwt {
        issuer: "my cool ca",
        subject: "my cool ca",
        spki: PublicKeyParams::Rsa {
            modulus: keys::KEY1_RSA_MOD,
            exponent: keys::KEY1_RSA_EXP,
        },
        key_usage: &[0b0010_0000],
        issuer_key: keys::KEY1_RSA_KEYPAIR,
    };

    let data = cwt.encode();
    let cert = Cert::parse(
        &data,
        CertFormat::OpenDiceCwt,
        None,
        &mut ring::sig::Ciphers::new(),
    )
    .unwrap();

    assert_eq!(cert.subject(), cert.issuer());
    assert!(cert.supports_cert_signing());
}
