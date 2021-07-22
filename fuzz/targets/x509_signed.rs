// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Fuzz tests for the X.509 certificate parser, including signature
//! validation.

#![no_main]

use libfuzzer_sys::fuzz_target;

use manticore::cert::Cert;
use manticore::cert::CertFormat;
use manticore::crypto::ring;

fuzz_target!(|data: &[u8]| {
    let cert = Cert::parse(
        data,
        CertFormat::RiotX509,
        None,
        &mut ring::sig::Ciphers::new()
    );

    // Since we're checking signatures, this is *guaranteed* to fail to verify.
    assert!(cert.is_err());
});
