// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [`crypto::rsa`] based on `ring`.
//!
//! Requires the `std` feature flag to be enabled.

use ring::error::Unspecified;
use ring::signature::KeyPair as _;
use ring::signature::RsaPublicKeyComponents;

use crate::crypto::rsa;

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
}

impl rsa::PublicKey for PublicKey {
    fn len(&self) -> rsa::ModulusLength {
        rsa::ModulusLength::from_byte_len(self.key.n.len())
            .expect("the keypair should already be a sanctioned size!")
    }
}

/// A `ring`-based [`rsa::Keypair`].
pub struct Keypair {
    keypair: ring::signature::RsaKeyPair,
}

impl Keypair {
    /// Creates a new `Keypair` from the given PKCS#8-encoded private key.
    ///
    /// This function will return `None` if parsing fails or if it is not one
    /// of the sanctioned sizes in [`rsa::ModulusLength`].
    pub fn from_pkcs8(pkcs8: &[u8]) -> Option<Self> {
        let keypair = ring::signature::RsaKeyPair::from_pkcs8(pkcs8).unwrap();
        rsa::ModulusLength::from_byte_len(keypair.public_modulus_len())
            .map(|_| Self { keypair })
    }
}

impl rsa::Keypair for Keypair {
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

/// A `ring`-based [`rsa::Builder`] and [`rsa::SignerBuilder`].
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

impl rsa::Builder for Builder {
    type Engine = Engine;

    fn supports_modulus(&self, _: rsa::ModulusLength) -> bool {
        true
    }

    fn new_engine(
        &self,
        key: PublicKey,
    ) -> Result<Engine, rsa::Error<Unspecified>> {
        Ok(Engine { key })
    }
}

impl rsa::SignerBuilder for Builder {
    type Signer = Signer;

    fn new_signer(
        &self,
        keypair: Keypair,
    ) -> Result<Signer, rsa::Error<Unspecified>> {
        Ok(Signer { keypair })
    }
}

/// A `ring`-based [`rsa::Engine`].
pub struct Engine {
    key: PublicKey,
}

impl rsa::Engine for Engine {
    type Error = Unspecified;
    type Key = PublicKey;

    fn verify_signature(
        &mut self,
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), rsa::Error<Unspecified>> {
        let scheme = &ring::signature::RSA_PKCS1_2048_8192_SHA256;
        self.key
            .key
            .verify(scheme, message, signature)
            .map_err(rsa::Error::Custom)
    }
}

/// A `ring`-based [`rsa::Signer`].
pub struct Signer {
    keypair: Keypair,
}

impl rsa::Signer for Signer {
    type Engine = Engine;
    type Keypair = Keypair;

    fn pub_len(&self) -> rsa::ModulusLength {
        use crate::crypto::rsa::Keypair as _;
        self.keypair.pub_len()
    }

    fn sign(
        &mut self,
        message: &[u8],
        signature: &mut [u8],
    ) -> Result<(), rsa::Error<Unspecified>> {
        let scheme = &ring::signature::RSA_PKCS1_SHA256;
        let rng = ring::rand::SystemRandom::new();
        self.keypair
            .keypair
            .sign(scheme, &rng, message, signature)
            .map_err(rsa::Error::Custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rsa;
    use crate::crypto::rsa::Builder as _;
    use crate::crypto::rsa::Engine as _;
    use crate::crypto::rsa::Keypair as _;
    use crate::crypto::rsa::Signer as _;
    use crate::crypto::rsa::SignerBuilder as _;
    use crate::crypto::testdata;

    #[test]
    fn rsa() {
        let keypair =
            Keypair::from_pkcs8(testdata::RSA_2048_PRIV_PKCS8).unwrap();
        assert_eq!(keypair.pub_len(), rsa::ModulusLength::Bits2048);

        let rsa = Builder::new();
        let mut engine = rsa.new_engine(keypair.public()).unwrap();
        engine
            .verify_signature(
                testdata::RSA_2048_SHA256_SIG_PKCS1,
                testdata::PLAIN_TEXT,
            )
            .unwrap();

        let mut signer = rsa.new_signer(keypair).unwrap();
        let mut generated_sig = vec![0; signer.pub_len().byte_len()];
        signer
            .sign(testdata::PLAIN_TEXT, &mut generated_sig)
            .unwrap();
        engine
            .verify_signature(&generated_sig, testdata::PLAIN_TEXT)
            .unwrap();
    }
}
