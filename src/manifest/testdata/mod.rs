// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Pre-baked manifest test data.
//!
//! Generated using
//! https://github.com/Azure/Project-Cerberus/blob/master/tools/testing/generate_pfm.sh.

/// PFM binary #1.
///
/// Generated with
/// ```text
/// $ ../generate_pfm.sh 42 src/crypto/testdata/rsa_2048_private_key.pem
/// ```
/// The JSON dump looks like this:
/// ```text
/// {
///   "version_id":42,
///   "elements": [
///     { "blank_byte": "0xff" },
///     {
///       "version_count": 1,
///       "firmware_id": [70, 105, 114, 109, 119, 97, 114, 101 ],
///       "flags": "0b0",
///       "children": [{
///         "version_addr": "0x12345",
///         "version_str": [84, 101, 115, 116, 105, 110, 103],
///         "rw_regions": [{
///           "flags": "0b0",
///           "region": { "offset": "0x2000000", "len": "0x2000000" }
///         }],
///         "image_regions": [{
///           "flags": "0b1",
///           "hash_type": "Sha256",
///           "hash": [
///             206, 158, 121, 205, 137, 192, 146,  23,
///              80, 117,  47, 191,  47, 174, 152, 150,
///               5, 144,  63, 223, 219, 138, 249,  90,
///             204,  56, 132,  89, 167, 118,  76,  28
///           ],
///           "regions": [{ "offset": "0x0", "len": "0x2000000" }]
///         }]
///       }]
///     }
///   ]
/// }
/// ```
pub const PFM_RSA1: &[u8] = include_bytes!("pfm1.bin");
