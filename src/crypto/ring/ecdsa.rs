// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of ECDSA based on `ring`.
//!
//! Requires the `std` feature flag to be enabled.

use ring::signature::EcdsaVerificationAlgorithm as EcdsaAlgo;
use ring::signature::VerificationAlgorithm as _;

use crate::crypto::sig;

/// A `ring`-based [`sig::Verify`] for DER-encoded ECDSA using the P-256 curve.
pub struct VerifyP256 {
    key: [u8; 65],
    algo: &'static EcdsaAlgo,
}

impl VerifyP256 {
    /// Creates a new `VerifyP256` using the DER encoding and the given
    /// public-key coordinates.
    pub fn with_der_encoding(x: [u8; 32], y: [u8; 32]) -> Self {
        let mut key = [4u8; 65];
        key[1..33].copy_from_slice(&x);
        key[33..64].copy_from_slice(&y);

        Self {
            key,
            algo: &ring::signature::ECDSA_P256_SHA256_ASN1,
        }
    }

    /// Creates a new `VerifyP256` using the PKCS#11 encoding and the given
    /// public-key coordinates.
    pub fn with_pkcs11_encoding(x: [u8; 32], y: [u8; 32]) -> Self {
        let mut key = [4u8; 65];
        key[1..33].copy_from_slice(&x);
        key[33..64].copy_from_slice(&y);

        Self {
            key,
            algo: &ring::signature::ECDSA_P256_SHA256_FIXED,
        }
    }
}

impl sig::Verify for VerifyP256 {
    fn verify(
        &mut self,
        message_vec: &[&[u8]],
        signature: &[u8],
    ) -> Result<(), sig::Error> {
        let mut message = Vec::new();
        for bytes in message_vec {
            message.extend_from_slice(bytes);
        }

        self.algo
            .verify(
                (&self.key[..]).into(),
                message.as_slice().into(),
                signature.into(),
            )
            .map_err(|_| sig::Error::Unspecified)
    }
}

/// A `ring`-based [`sig::Sign`] for PKCS#1.5 RSA using SHA-256.
pub struct SignP256 {
    keypair: ring::signature::EcdsaKeyPair,
}

impl SignP256 {
    /// Creates a new `SignP256` from the given PKCS#8-encoded private key,
    /// using the DER encoding for signatures.
    ///
    /// Returns `None` if the key fails to parse.
    pub fn with_der_encoding_from_pkcs8(
        pkcs8: &[u8],
    ) -> Result<Self, sig::Error> {
        let keypair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8,
        )
        .map_err(|_| sig::Error::Unspecified)?;
        Ok(Self { keypair })
    }

    /// Creates a new `SignP256` from the given PKCS#8-encoded private key,
    /// using the PKCS#11-style encoding for signatures.
    ///
    /// Returns `None` if the key fails to parse.
    pub fn with_pkcs11_encoding_from_pkcs8(
        pkcs8: &[u8],
    ) -> Result<Self, sig::Error> {
        let keypair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8,
        )
        .map_err(|_| sig::Error::Unspecified)?;
        Ok(Self { keypair })
    }
}

impl sig::Sign for SignP256 {
    fn sig_bytes(&self) -> usize {
        // The encoding is the following ASN.1 struct:
        // SEQUENCE { r INTEGER, s INTEGER }
        //
        // Therefore, we have up to 64 bytes of point coordinates, plus:
        // - Two bytes for leading INTEGER zeros.
        // - Two bytes for `r` and `s` lengths.
        // - Two bytes for `r` and `s` tags.
        // - Two bytes for the overall SEQUENCE header.
        //
        // See:
        // https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3
        64 + 8
    }

    fn sign(
        &mut self,
        message_vec: &[&[u8]],
        signature: &mut [u8],
    ) -> Result<(), sig::Error> {
        let mut message = Vec::new();
        for bytes in message_vec {
            message.extend_from_slice(bytes);
        }

        let rng = ring::rand::SystemRandom::new();
        let sig = self
            .keypair
            .sign(&rng, &message)
            .map_err(|_| sig::Error::Unspecified)?;
        if signature.len() != sig.as_ref().len() {
            return Err(sig::Error::Unspecified);
        }
        signature.copy_from_slice(sig.as_ref());
        Ok(())
    }
}
