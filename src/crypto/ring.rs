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

/// A `ring`-based `rsa::PublicKey<>`.
#[derive(Clone)]
pub struct RsaPubKey {
    key: RsaPublicKeyComponents<Box<[u8]>>,
}

impl RsaPubKey {
    /// Creates a new `RsaPubKey` with the given modulus, and with the standard
    /// `0x10001` exponent.
    ///
    /// Panics if the key modulus is not of one of the sanctioned sizes
    /// in `rsa::ModulusLength`.
    pub fn new(modulus: Box<[u8]>) -> Self {
        let bit_len = modulus.len() * 8;
        if bit_len != 2048 && bit_len != 3072 && bit_len != 4096 {
            panic!("unexpected modulus length: {}", bit_len);
        }

        Self {
            key: RsaPublicKeyComponents {
                n: modulus,
                // NOTE: ring requires big-endian.
                e: vec![0x01, 0x00, 0x01].into_boxed_slice(),
            },
        }
    }

    /// Creates a new `RsaPubKey` by parsing a private RSA key and computing
    /// a public key from it.
    ///
    /// This function will panic if any parsing errors occur; it is expected
    /// that this function is ever only used with known-good test data.
    ///
    /// This function will also panic if the public exponent is not `0x10001`
    /// or if the key size is not one of the sanctioned sizes in
    /// `rsa::ModulusLength`.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Self {
        use ring::signature::KeyPair as _;
        let keypair = ring::signature::RsaKeyPair::from_pkcs8(pkcs8).unwrap();

        assert_eq!(
            keypair
                .public_key()
                .exponent()
                .big_endian_without_leading_zero(),
            &[1, 0, 1]
        );

        let n = keypair
            .public_key()
            .modulus()
            .big_endian_without_leading_zero()
            .to_vec()
            .into_boxed_slice();
        Self::new(n)
    }
}

impl rsa::PublicKey for RsaPubKey {
    fn len(&self) -> rsa::ModulusLength {
        match self.key.n.len() * 8 {
            2048 => rsa::ModulusLength::Bits2048,
            3072 => rsa::ModulusLength::Bits3072,
            4096 => rsa::ModulusLength::Bits4096,
            _ => unreachable!(),
        }
    }
}

/// A `ring`-based `rsa::Builder`.
///
/// This type also provides static functions for generating signatures
/// for use by tests.
pub struct Rsa;

impl Rsa {
    /// Creates an RSA-SHA256 PKCS v1.5 signature for `msg` using the given
    /// PKCS#8-encoded private key.
    ///
    /// This function will panic if it encounters any errors.
    pub fn sign_with_pkcs8(pkcs8: &[u8], msg: &[u8]) -> Box<[u8]> {
        let keypair = ring::signature::RsaKeyPair::from_pkcs8(pkcs8).unwrap();

        let scheme = &ring::signature::RSA_PKCS1_SHA256;
        let rng = ring::rand::SystemRandom::new();
        let mut output = vec![0; keypair.public_modulus_len()];
        keypair.sign(scheme, &rng, msg, &mut output).unwrap();
        output.into_boxed_slice()
    }
}

impl rsa::Builder for Rsa {
    type Engine = RsaEngine;

    fn supports_modulus(&self, _: rsa::ModulusLength) -> bool {
        true
    }

    fn new_engine(&self, key: RsaPubKey) -> Result<RsaEngine, Unspecified> {
        Ok(RsaEngine { key })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rsa;
    use crate::crypto::rsa::Builder as _;
    use crate::crypto::rsa::Engine as _;
    use crate::crypto::rsa::PublicKey as _;
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
        let key = RsaPubKey::from_pkcs8(testdata::RSA_2048_PRIV_PKCS8);
        assert_eq!(key.len(), rsa::ModulusLength::Bits2048);

        let rsa = Rsa;
        let mut engine = rsa.new_engine(key).unwrap();
        engine
            .verify_signature(
                testdata::RSA_2048_SHA256_SIG_PKCS1,
                testdata::PLAIN_TEXT,
            )
            .unwrap();

        let generated_sig = Rsa::sign_with_pkcs8(
            testdata::RSA_2048_PRIV_PKCS8,
            testdata::PLAIN_TEXT,
        );
        engine
            .verify_signature(&generated_sig, testdata::PLAIN_TEXT)
            .unwrap();
    }
}
