// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Fuzz tests for the X.509 certificate parser, including signature
//! validation.

#![no_main]

use libfuzzer_sys::fuzz_target;

use manticore::cert::Cert;
use manticore::cert::CertFormat;
use manticore::crypto::sig;
use manticore::protocol::capabilities;

/// A `Ciphers` that blindly accepts all signatures.
struct NoVerify;

impl sig::Verify for NoVerify {
    fn verify(
        &mut self,
        _: &[&[u8]],
        _: &[u8],
    ) -> Result<(), sig::Error> {
        Ok(())
    }
}

impl sig::Ciphers for NoVerify {
    fn negotiate(&self, _: &mut capabilities::Crypto) {}
    fn verifier<'a>(
        &'a mut self,
        _: sig::Algo,
        _: &sig::PublicKeyParams,
    ) -> Option<&'a mut dyn sig::Verify> {
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
