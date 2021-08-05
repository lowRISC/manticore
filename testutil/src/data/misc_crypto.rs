// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Miscellaneous cryptograhic test data that isn't worth maintaining custom
//! scripts for.

/// A plaintext string.
pub const PLAIN_TEXT: &[u8] = b"I'm setting the alarm clock for July.";

/// The SHA-256 hash of `PLAIN_TEXT`.
///
/// Generate with:
/// ```text
/// openssl dgst -sha256 \
///   <<< "I'm setting the alarm clock for July." \
///   | xxd -i -c 8
/// ```
#[rustfmt::skip]
pub const PLAIN_SHA256: &[u8] = &[
    0xc9, 0xfd, 0xba, 0xae, 0x28, 0xe7, 0x49, 0x5c,
    0xe1, 0x13, 0xbc, 0x87, 0xc8, 0x20, 0x6c, 0xba,
    0xc2, 0xd1, 0x0c, 0x28, 0x17, 0xf0, 0x06, 0x11,
    0xd0, 0xc6, 0x19, 0x2f, 0x47, 0x64, 0xdb, 0xba,
];

/// An RSA signature for `PLAIN_TEXT`, generated thus:
///
/// ```text
/// openssl dgst -sha256 -keyform DER \
///   -sign testutil/src/data/keys/key1.rsa.pk8 \
///   <<< "I'm setting the alarm clock for July." \
///   | xxd -i -c 8
/// ```
///
/// The signature is in PKCS v1.5 format.
#[rustfmt::skip]
pub const KEY1_SHA256_SIG: &[u8] = &[
    0x4d, 0xd8, 0x99, 0xbf, 0x42, 0xc0, 0xef, 0xf4,
    0xd6, 0x5f, 0xb6, 0xa4, 0x9c, 0xeb, 0x63, 0xc3,
    0x06, 0x00, 0xc3, 0xaa, 0x7e, 0xcb, 0x78, 0x8e,
    0x13, 0xc6, 0xbb, 0xbc, 0x5a, 0x05, 0x34, 0xb8,
    0xe8, 0xa9, 0xef, 0x43, 0xa8, 0x2d, 0x63, 0xe8,
    0x64, 0xc4, 0x5d, 0x32, 0xaa, 0xed, 0x15, 0xf8,
    0xf6, 0x1a, 0xeb, 0x95, 0xc3, 0x4d, 0x09, 0x91,
    0x3b, 0xdd, 0x69, 0x94, 0x4f, 0xd6, 0x16, 0xca,
    0x50, 0x88, 0x2d, 0xcf, 0xe7, 0x94, 0x43, 0x9c,
    0xd8, 0xbd, 0x68, 0xdd, 0xdb, 0x48, 0xab, 0x60,
    0xd5, 0xca, 0x34, 0xab, 0x18, 0x69, 0xb9, 0x34,
    0xca, 0x5a, 0x3d, 0xdd, 0x65, 0xde, 0x51, 0x8d,
    0x54, 0x67, 0x2b, 0xd1, 0x4e, 0xae, 0x8d, 0xcd,
    0xa5, 0xaa, 0x62, 0x5d, 0xa0, 0x30, 0x97, 0xd9,
    0x91, 0x38, 0xd4, 0x81, 0x83, 0x7c, 0xf9, 0xc5,
    0xbe, 0xc5, 0xef, 0xfc, 0x34, 0x21, 0xce, 0x27,
    0x81, 0xf2, 0x79, 0x51, 0x3a, 0x3b, 0x02, 0x2d,
    0xe6, 0x1d, 0x0f, 0x38, 0x77, 0x63, 0xbd, 0x30,
    0xce, 0x39, 0x63, 0x8a, 0x63, 0x7e, 0x1e, 0x0b,
    0xb5, 0x39, 0xd5, 0xa7, 0x42, 0xb0, 0x1d, 0x69,
    0x02, 0x81, 0x9a, 0x65, 0x4d, 0x51, 0xfd, 0x0b,
    0xc5, 0x57, 0x20, 0xae, 0x2e, 0xf8, 0x62, 0x6b,
    0xce, 0x35, 0xb6, 0xd4, 0x9b, 0x0a, 0x5e, 0x26,
    0xfa, 0x10, 0x54, 0x5a, 0x95, 0x57, 0xe2, 0xd8,
    0xf3, 0xa4, 0x1a, 0x11, 0x07, 0x40, 0xec, 0x3d,
    0x84, 0x99, 0x56, 0xe1, 0x63, 0x7f, 0xec, 0x35,
    0x5d, 0xf2, 0x3d, 0x21, 0xb2, 0x74, 0x42, 0x02,
    0xad, 0xcb, 0x42, 0x7e, 0x45, 0x40, 0xef, 0x93,
    0x23, 0xdd, 0x7d, 0xce, 0xcc, 0x6c, 0x63, 0x45,
    0x9e, 0x26, 0x7b, 0x7c, 0x9a, 0xea, 0x07, 0x15,
    0x33, 0x36, 0xcc, 0x3c, 0x96, 0x46, 0xbf, 0x79,
    0x07, 0x3c, 0x3c, 0x9d, 0x8c, 0x72, 0x0c, 0x79,
];
