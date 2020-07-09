// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use manticore::crypto::rsa;
use manticore::manifest::Manifest;

/// An `rsa::Engine` that actually doesn't do anything, since signature
/// verification is irrelevant for the purposes of this test.
struct NoCheckRsa;

impl rsa::PublicKey for NoCheckRsa {
    fn len(&self) -> rsa::ModulusLength {
        unimplemented!("the code under test should never call this function")
    }
}

impl rsa::Engine for NoCheckRsa {
    type Key = Self;
    type Error = ();

    fn verify_signature(&mut self, _: &[u8], _: &[u8]) -> Result<(), ()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = Manifest::parse_and_verify(data, &mut NoCheckRsa);
});
