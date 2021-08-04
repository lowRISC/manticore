// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [`crypto::sig`] based on [`ring`].
//!
//! Requires the `std` feature flag to be enabled.

use crate::crypto::ring::rsa;
use crate::crypto::rsa::Builder as _;
use crate::crypto::sig;
use crate::protocol::capabilities;

#[cfg(doc)]
use crate::crypto;

/// A [`sig::Ciphers`] built on top of `ring`.
#[derive(Default)]
pub struct Ciphers {
    verifier: Option<Box<dyn sig::Verify>>,
}

impl Ciphers {
    /// Returns a new `RingCiphers`.
    pub fn new() -> Self {
        Default::default()
    }
}

impl sig::Ciphers for Ciphers {
    fn negotiate(&self, caps: &mut capabilities::Crypto) {
        use capabilities::*;
        *caps = Crypto {
            has_ecdsa: false,
            has_ecc: false,
            has_rsa: true,

            ecc_strength: EccKeyStrength::empty(),
            rsa_strength: RsaKeyStrength::from_builder(&rsa::Builder::new()),
            ..*caps
        };
    }

    fn verifier<'a>(
        &'a mut self,
        algo: sig::Algo,
        key: &sig::PublicKeyParams,
    ) -> Option<&'a mut dyn sig::Verify> {
        match (algo, key) {
            (
                sig::Algo::RsaPkcs1Sha256,
                sig::PublicKeyParams::Rsa { modulus, exponent },
            ) => {
                let key =
                    rsa::PublicKey::new((*modulus).into(), (*exponent).into())?;

                let rsa = rsa::Builder::new();
                self.verifier = Some(Box::new(rsa.new_verifier(key).ok()?));
                self.verifier.as_mut().map(|x| &mut **x as _)
            }
        }
    }
}
