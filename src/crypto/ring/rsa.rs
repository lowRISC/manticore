// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of RSA based on `ring`.
//!
//! Requires the `std` feature flag to be enabled.

use ring::signature::KeyPair as _;
use ring::signature::RsaPublicKeyComponents;

use crate::crypto::sig;

#[cfg(doc)]
use crate::crypto;

/// An RSA public key.
#[derive(Clone)]
pub struct PublicKey {
    key: RsaPublicKeyComponents<Box<[u8]>>,
}

impl PublicKey {
    /// Creates a new `PublicKey` with the given modulus and exponent, both of
    /// which should be given in big-endian, padded with zeroes out to the
    /// desired bit length.
    pub fn new(modulus: Box<[u8]>, exponent: Box<[u8]>) -> Self {
        Self {
            key: RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            },
        }
    }
}

/// A `ring`-based [`sig::Verify`] for PKCS#1.5 RSA using SHA-256.
pub struct Verify256 {
    key: PublicKey,
}

impl Verify256 {
    /// Creates a new `Verify256` with the given key.
    pub fn from_public(key: PublicKey) -> Self {
        Self { key }
    }
}

impl sig::Verify for Verify256 {
    fn verify(
        &mut self,
        message_vec: &[&[u8]],
        signature: &[u8],
    ) -> Result<(), sig::Error> {
        let mut message = Vec::new();
        for bytes in message_vec {
            message.extend_from_slice(bytes);
        }

        let scheme = &ring::signature::RSA_PKCS1_2048_8192_SHA256;
        self.key
            .key
            .verify(scheme, &message, signature)
            .map_err(|_| sig::Error::Unspecified)
    }
}

/// A `ring`-based [`sig::Sign`] for PKCS#1.5 RSA using SHA-256.
pub struct Sign256 {
    keypair: ring::signature::RsaKeyPair,
}

impl Sign256 {
    /// Creates a new `Sign256` from the given PKCS#8-encoded private key.
    ///
    /// Returns `None` if the key fails to parse.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, sig::Error> {
        let keypair = ring::signature::RsaKeyPair::from_pkcs8(pkcs8)
            .map_err(|_| sig::Error::Unspecified)?;
        Ok(Self { keypair })
    }

    /// Creates a `Verify256` using a copy of the corresponding public key.
    pub fn verifier(&self) -> Verify256 {
        let n = self
            .keypair
            .public_key()
            .modulus()
            .big_endian_without_leading_zero()
            .to_vec()
            .into_boxed_slice();
        let e = self
            .keypair
            .public_key()
            .exponent()
            .big_endian_without_leading_zero()
            .to_vec()
            .into_boxed_slice();
        Verify256 {
            key: PublicKey::new(n, e),
        }
    }
}

impl sig::Sign for Sign256 {
    fn sig_bytes(&self) -> usize {
        self.keypair.public_modulus_len()
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

        let scheme = &ring::signature::RSA_PKCS1_SHA256;
        let rng = ring::rand::SystemRandom::new();
        self.keypair
            .sign(scheme, &rng, &message, signature)
            .map_err(|_| sig::Error::Unspecified)
    }
}

/// Generates an RSA engine and signer out of test-only data.
#[cfg(test)]
pub fn from_keypair(keypair: &[u8]) -> (Verify256, Sign256) {
    let signer = Sign256::from_pkcs8(keypair).unwrap();
    let verifier = signer.verifier();
    (verifier, signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sig::Sign as _;
    use crate::crypto::sig::Verify as _;
    use testutil::data::keys;
    use testutil::data::misc_crypto;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rsa() {
        let (mut verifier, mut signer) = from_keypair(keys::KEY1_RSA_KEYPAIR);

        verifier
            .verify(&[misc_crypto::PLAIN_TEXT], misc_crypto::KEY1_SHA256_SIG)
            .unwrap();

        let mut generated_sig = vec![0; signer.sig_bytes()];
        signer
            .sign(&[misc_crypto::PLAIN_TEXT], &mut generated_sig)
            .unwrap();

        verifier
            .verify(&[misc_crypto::PLAIN_TEXT], &generated_sig)
            .unwrap();
    }
}
