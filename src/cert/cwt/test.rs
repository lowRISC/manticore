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
use crate::crypto::sig::Sign as _;

const UINT: u8 = 0;
const NINT: u8 = 1;
const UTF8: u8 = 3;
const BYTES: u8 = 2;
const ARRAY: u8 = 4;
const MAP: u8 = 5;

#[test]
#[cfg_attr(miri, ignore)]
fn self_signed() {
    let protected = raw_cbor!(MAP [
        // Algorithm.
        UINT:1  NINT:256,
        // Criticalities.
        UINT:2  ARRAY[UINT:1, UINT:2],
    ]);
    let payload = raw_cbor!(MAP [
        // Issuer.
        UINT:1  UTF8 {"my cool ca"},
        // Subject; self-signed.
        UINT:2  UTF8 {"my cool ca"},

        // DICE SPKI.
        NINT:4670551    MAP [
            // Key type, RSA.
            UINT:1  UINT:3,
            // Algorithm,i RSA.
            UINT:3  NINT:256,
            // Modulus.
            NINT:0  BYTES {h"
                a6be96e18c5c826a748b887b194ed3f6
                daaa8897cdbaee69e5a980b9dab5af7e
                5f4fed0236d78400837b28229fd4ee24
                1c0d6f3178651265a2762aa1f449dcec
                2a8b679058f9c97a3ba93a7c2bb6d62d
                3baaa70a47991ee6f0daefc55892035f
                a4f4d1c493a73bf61018c6cf86bb43aa
                151f9f0bfa5f474a7fa2bba6a1c77e17
                e160cee2387586e43ff78efd95327d22
                0fc12b0e717089b18cf667ce672d6351
                d187d9330b8777cbe2fb28fccba0b2ad
                c560c9d03e2cba50d624736545c587cc
                0f1d3ef3d7ec69f4108fff270455155b
                d9a3d72c41a397915bad3c9aba753e7b
                f91614d25642cd968816108647e2f7a8
                580e4c05ff0a7f233beba82ca8569a53
            "},
            // Exponent.
            NINT:1  BYTES {h"010001"},
        ],
        // DICE KeyUsage
        NINT:4670552    BYTES {[0b0010_0000]},
    ]);

    let tbs = raw_cbor!(ARRAY [
        UTF8 {"Signature1"},
        BYTES {protected},
        BYTES {},
        BYTES {payload},
    ]);

    let (_, mut signer) = ring::rsa::from_keypair(keys::KEY1_RSA_KEYPAIR);
    let mut sig = vec![0; signer.sig_bytes()];
    signer.sign(&[&tbs], &mut sig).unwrap();

    let data = raw_cbor! {
        BYTES {protected}
        MAP []
        BYTES {payload}
        BYTES {sig}
    };

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
