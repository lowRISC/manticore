// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [`crypto::sig`] based on [`ring`].
//!
//! Requires the `std` feature flag to be enabled.

use core::convert::TryInto as _;

use crate::crypto::ring::ecdsa;
use crate::crypto::ring::rsa;
use crate::crypto::sig;
use crate::crypto::sig::Algo;
use crate::crypto::sig::Curve;
use crate::crypto::sig::PublicKeyParams;
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
            has_ecdsa: true,
            has_ecc: true,
            has_rsa: true,

            ecc_strength: EccKeyStrength::BITS_256,
            rsa_strength: RsaKeyStrength::all(),
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
                Algo::RsaPkcs1Sha256,
                PublicKeyParams::Rsa { modulus, exponent },
            ) => {
                let key =
                    rsa::PublicKey::new((*modulus).into(), (*exponent).into());

                self.verifier =
                    Some(Box::new(rsa::Verify256::from_public(key)));
            }
            (
                Algo::EcdsaDerP256,
                PublicKeyParams::Ecc {
                    curve: Curve::NistP256,
                    x,
                    y,
                },
            ) => {
                let x: &[u8; 32] = (*x).try_into().ok()?;
                let y: &[u8; 32] = (*y).try_into().ok()?;
                self.verifier = Some(Box::new(
                    ecdsa::VerifyP256::with_der_encoding(*x, *y),
                ));
            }
            (
                Algo::EcdsaPkcs11P256,
                PublicKeyParams::Ecc {
                    curve: Curve::NistP256,
                    x,
                    y,
                },
            ) => {
                let x: &[u8; 32] = (*x).try_into().ok()?;
                let y: &[u8; 32] = (*y).try_into().ok()?;
                self.verifier = Some(Box::new(
                    ecdsa::VerifyP256::with_pkcs11_encoding(*x, *y),
                ));
            }
            _ => {}
        }

        self.verifier.as_mut().map(|x| &mut **x as _)
    }
}
