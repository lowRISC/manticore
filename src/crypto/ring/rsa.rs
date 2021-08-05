// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [`crypto::rsa`] based on `ring`.
//!
//! Requires the `std` feature flag to be enabled.

use ring::signature::KeyPair as _;
use ring::signature::RsaPublicKeyComponents;

use crate::crypto::rsa;
use crate::crypto::sig;

#[cfg(doc)]
use crate::crypto;

/// A `ring`-based [`rsa::PublicKey`].
#[derive(Clone)]
pub struct PublicKey {
    key: RsaPublicKeyComponents<Box<[u8]>>,
}

impl PublicKey {
    /// Creates a new `PublicKey` with the given modulus and exponent, both of
    /// which should be given in big-endian, padded with zeroes out to the
    /// desired bit length.
    ///
    /// Returns `None` if the key modulus is not of one of the sanctioned sizes
    /// in [`rsa::ModulusLength`].
    pub fn new(modulus: Box<[u8]>, exponent: Box<[u8]>) -> Option<Self> {
        rsa::ModulusLength::from_byte_len(modulus.len()).map(|_| Self {
            key: RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            },
        })
    }

    /// Converts this `PublicKey` in a form useable by Manticore's certificate
    /// parsers.
    pub fn as_cert_params(&self) -> sig::PublicKeyParams {
        sig::PublicKeyParams::Rsa {
            modulus: &self.key.n,
            exponent: &self.key.e,
        }
    }
}

impl rsa::PublicKey for PublicKey {
    fn len(&self) -> rsa::ModulusLength {
        rsa::ModulusLength::from_byte_len(self.key.n.len())
            .expect("the keypair should already be a sanctioned size!")
    }
}

/// A `ring`-based [`rsa::KeyPair`].
pub struct KeyPair {
    keypair: ring::signature::RsaKeyPair,
}

impl KeyPair {
    /// Creates a new `KeyPair` from the given PKCS#8-encoded private key.
    ///
    /// This function will return `None` if parsing fails or if it is not one
    /// of the sanctioned sizes in [`rsa::ModulusLength`].
    pub fn from_pkcs8(pkcs8: &[u8]) -> Option<Self> {
        let keypair = ring::signature::RsaKeyPair::from_pkcs8(pkcs8).unwrap();
        rsa::ModulusLength::from_byte_len(keypair.public_modulus_len())
            .map(|_| Self { keypair })
    }
}

impl rsa::KeyPair for KeyPair {
    type Pub = PublicKey;
    fn public(&self) -> Self::Pub {
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
        PublicKey::new(n, e)
            .expect("the keypair should already be a sanctioned size!")
    }

    fn pub_len(&self) -> rsa::ModulusLength {
        rsa::ModulusLength::from_byte_len(self.keypair.public_modulus_len())
            .expect("the keypair should already be a sanctioned size!")
    }
}

/// A `ring`-based [`rsa::Builder`].
pub struct Builder {
    _priv: (),
}

impl Builder {
    /// Creates a new `Builder`.
    pub fn new() -> Self {
        Builder { _priv: () }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl rsa::Builder<rsa::RsaPkcs1Sha256> for Builder {
    type Verify = Verify256;
    type Sign = Sign256;

    type Key = PublicKey;
    type KeyPair = KeyPair;

    fn new_signer(
        &self,
        keypair: Self::KeyPair,
    ) -> Result<Self::Sign, sig::Error> {
        Ok(Self::Sign { keypair })
    }

    fn supports_modulus(&self, _: rsa::ModulusLength) -> bool {
        true
    }

    fn new_verifier(&self, key: PublicKey) -> Result<Self::Verify, sig::Error> {
        Ok(Self::Verify { key })
    }
}

/// A `ring`-based [`sig::Verify`] for PKCS#1.5 RSA using SHA-256.
pub struct Verify256 {
    key: PublicKey,
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
impl sig::VerifyFor<rsa::RsaPkcs1Sha256> for Verify256 {}

/// A `ring`-based [`sig::Sign`] for PKCS#1.5 RSA using SHA-256.
pub struct Sign256 {
    keypair: KeyPair,
}

impl sig::Sign for Sign256 {
    fn sig_bytes(&self) -> usize {
        use crate::crypto::rsa::KeyPair as _;
        self.keypair.pub_len().byte_len()
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
            .keypair
            .sign(scheme, &rng, &message, signature)
            .map_err(|_| sig::Error::Unspecified)
    }
}
impl sig::SignFor<rsa::RsaPkcs1Sha256> for Sign256 {}

/// Generates an RSA engine and signer out of test-only data.
#[cfg(test)]
pub fn from_keypair(keypair: &[u8]) -> (Verify256, Sign256) {
    use crate::crypto::rsa::Builder as _;
    use crate::crypto::rsa::KeyPair as _;
    let keypair = KeyPair::from_pkcs8(keypair).unwrap();
    let pub_key = keypair.public();
    let rsa_builder = Builder::new();
    let rsa = rsa_builder.new_verifier(pub_key).unwrap();
    let signer = rsa_builder.new_signer(keypair).unwrap();
    (rsa, signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    use testutil::data::keys;
    use testutil::data::misc_crypto;

    use crate::crypto::rsa::Builder as _;
    use crate::crypto::rsa::KeyPair as _;
    use crate::crypto::rsa::ModulusLength;
    use crate::crypto::sig::Sign as _;
    use crate::crypto::sig::Verify as _;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rsa() {
        let keypair = KeyPair::from_pkcs8(keys::KEY1_RSA_KEYPAIR).unwrap();
        assert_eq!(keypair.pub_len(), ModulusLength::Bits2048);

        let rsa = Builder::new();
        let mut engine = rsa.new_verifier(keypair.public()).unwrap();

        engine
            .verify(&[misc_crypto::PLAIN_TEXT], misc_crypto::KEY1_SHA256_SIG)
            .unwrap();

        let mut signer = rsa.new_signer(keypair).unwrap();
        let mut generated_sig = vec![0; signer.sig_bytes()];
        signer
            .sign(&[misc_crypto::PLAIN_TEXT], &mut generated_sig)
            .unwrap();
        engine
            .verify(&[misc_crypto::PLAIN_TEXT], &generated_sig)
            .unwrap();
    }
}
