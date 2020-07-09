// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of crypto traits, using the `ring` crate.
//!
//! This module provides test-only implementations of `manticore::crypto`
//! traits based on Brian Smith's `ring` crate. At the moment, they are not
//! intended for use in a `manticore` integration.
//!
//! In particular, this module is not `no_std`, and takes no care to be
//! side-channel-free, beyond whatever precautions `ring` takes.

use std::convert::Infallible;

use ring::digest;
use ring::error::Unspecified;
use ring::signature::KeyPair as _;
use ring::signature::RsaPublicKeyComponents;

use crate::crypto::rsa;
use crate::crypto::sha256;

/// A `ring`-based `sha256::Builder`.
pub struct Sha;

impl sha256::Builder for Sha {
    type Hasher = ShaHasher;

    fn new_hasher(&self) -> Result<ShaHasher, Infallible> {
        Ok(ShaHasher {
            ctx: digest::Context::new(&digest::SHA256),
        })
    }
}

/// A `ring`-based `sha256::Hasher`.
pub struct ShaHasher {
    ctx: digest::Context,
}

impl sha256::Hasher for ShaHasher {
    type Error = Infallible;

    fn write(&mut self, bytes: &[u8]) -> Result<(), Infallible> {
        self.ctx.update(bytes);
        Ok(())
    }

    fn finish(self, out: &mut sha256::Digest) -> Result<(), Infallible> {
        let digest = self.ctx.finish();
        out.copy_from_slice(digest.as_ref());
        Ok(())
    }
}

/// A `ring`-based `rsa::PublicKey`.
#[derive(Clone)]
pub struct RsaPubKey {
    key: RsaPublicKeyComponents<Box<[u8]>>,
}

impl RsaPubKey {
    /// Creates a new `RsaPubKey` with the given modulus and exponent, both of
    /// which should be given in big-endian, padded with zeroes out to the
    /// desired bit length.
    ///
    /// Returns `None` if the key modulus is not of one of the sanctioned sizes
    /// in `rsa::ModulusLength`.
    pub fn new(modulus: Box<[u8]>, exponent: Box<[u8]>) -> Option<Self> {
        rsa::ModulusLength::from_byte_len(modulus.len()).map(|_| Self {
            key: RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            },
        })
    }
}

impl rsa::PublicKey for RsaPubKey {
    fn len(&self) -> rsa::ModulusLength {
        rsa::ModulusLength::from_byte_len(self.key.n.len())
            .expect("the keypair should already be a sanctioned size!")
    }
}

/// A `ring`-based `rsa::Keypair`.
pub struct RsaKeypair {
    keypair: ring::signature::RsaKeyPair,
}

impl RsaKeypair {
    /// Creates a new `RsaKeyPair` from the given PKCS#8-encoded private key.
    ///
    /// This function will return `None` if parsing fails or if it is not one
    /// of the sanctioned sizes in `rsa::ModulusLength`.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Option<Self> {
        let keypair = ring::signature::RsaKeyPair::from_pkcs8(pkcs8).unwrap();
        rsa::ModulusLength::from_byte_len(keypair.public_modulus_len())
            .map(|_| Self { keypair })
    }
}

impl rsa::Keypair for RsaKeypair {
    type Pub = RsaPubKey;
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
        RsaPubKey::new(n, e)
            .expect("the keypair should already be a sanctioned size!")
    }

    fn pub_len(&self) -> rsa::ModulusLength {
        rsa::ModulusLength::from_byte_len(self.keypair.public_modulus_len())
            .expect("the keypair should already be a sanctioned size!")
    }
}

/// A `ring`-based `rsa::Builder` and `rsa::SignerBuilder`.
pub struct Rsa;

impl rsa::Builder for Rsa {
    type Engine = RsaEngine;

    fn supports_modulus(&self, _: rsa::ModulusLength) -> bool {
        true
    }

    fn new_engine(&self, key: RsaPubKey) -> Result<RsaEngine, Unspecified> {
        Ok(RsaEngine { key })
    }
}

impl rsa::SignerBuilder for Rsa {
    type Signer = RsaSigner;

    fn new_signer(
        &self,
        keypair: RsaKeypair,
    ) -> Result<RsaSigner, Unspecified> {
        Ok(RsaSigner { keypair })
    }
}

/// A `ring`-based `rsa::Engine`.
pub struct RsaEngine {
    key: RsaPubKey,
}

impl rsa::Engine for RsaEngine {
    type Error = Unspecified;
    type Key = RsaPubKey;

    fn verify_signature(
        &mut self,
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), Unspecified> {
        let scheme = &ring::signature::RSA_PKCS1_2048_8192_SHA256;
        self.key.key.verify(scheme, message, signature)
    }
}

pub struct RsaSigner {
    keypair: RsaKeypair,
}

impl rsa::Signer for RsaSigner {
    type Engine = RsaEngine;
    type Keypair = RsaKeypair;

    fn pub_len(&self) -> rsa::ModulusLength {
        use crate::crypto::rsa::Keypair as _;
        self.keypair.pub_len()
    }

    fn sign(
        &mut self,
        message: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Unspecified> {
        let scheme = &ring::signature::RSA_PKCS1_SHA256;
        let rng = ring::rand::SystemRandom::new();
        self.keypair.keypair.sign(scheme, &rng, message, signature)
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
    use crate::crypto::sha256;
    use crate::crypto::sha256::Builder as _;
    use crate::crypto::sha256::Hasher as _;
    use crate::crypto::testdata;

    #[test]
    fn sha() {
        let sha = Sha;
        let mut digest = sha256::Digest::default();

        let mut hasher = sha.new_hasher().unwrap();
        hasher.write(testdata::PLAIN_TEXT).unwrap();
        hasher.finish(&mut digest).unwrap();
        assert_eq!(&digest, testdata::PLAIN_SHA256);

        let mut hasher = sha.new_hasher().unwrap();
        hasher.write(&testdata::PLAIN_TEXT[..16]).unwrap();
        hasher.write(&testdata::PLAIN_TEXT[16..]).unwrap();
        hasher.finish(&mut digest).unwrap();
        assert_eq!(&digest, testdata::PLAIN_SHA256);
    }

    #[test]
    fn rsa() {
        let keypair =
            RsaKeypair::from_pkcs8(testdata::RSA_2048_PRIV_PKCS8).unwrap();
        assert_eq!(keypair.pub_len(), rsa::ModulusLength::Bits2048);

        let rsa = Rsa;
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
