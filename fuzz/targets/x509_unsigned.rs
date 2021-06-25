// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Fuzz tests for the X.509 certificate parser, including signature
//! validation.

#![no_main]

use libfuzzer_sys::fuzz_target;

use manticore::cert;
use manticore::cert::Algo;
use manticore::cert::Cert;
use manticore::cert::CertFormat;
use manticore::cert::PublicKeyParams;
use manticore::crypto::sig;

/// A `Ciphers` that blindly accepts all signatures.
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

fuzz_target!(|data: &[u8]| {
    let _ = Cert::parse(
        data,
        CertFormat::RiotX509,
        None,
        &mut NoVerify,
    );

    // NOTE: we might actually succeed at creating a valid cert, so we can't
    // check for is_err() here.
});
