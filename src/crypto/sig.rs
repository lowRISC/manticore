// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Algorithm-generic signature traits.

use crate::protocol::capabilities;

/// An error returned by a signature operation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Indicates an unspecified, internal error.
    Unspecified,
}

/// A signature-verification engine, already primed with a key.
///
/// There is no way to extract the key back out of a `Verify` value.
pub trait Verify {
    /// Verifies that `signature` is a valid signature for `message_vec`.
    ///
    /// `message_vec` is an iovec-like structure: the message is split across
    /// many buffers for digital signatures that are the concatenation of many
    /// parts, such as the Cerberus challenge command or a CWT signature.
    ///
    /// If the underlying cryptographic operation succeeds, returns `Ok(())`.
    /// Failures, including signature check failures, are included in the
    /// `Err` variant.
    fn verify(
        &mut self,
        message_vec: &[&[u8]],
        signature: &[u8],
    ) -> Result<(), Error>;
}

/// An signing engine, already primed with a keypair.
///
/// There is no way to extract the keypair back out of a `Sign` value.
pub trait Sign {
    /// Returns the number of bytes a signature produced by this signer needs.
    fn sig_bytes(&self) -> usize;

    /// Creates a digital signature for `message_vec`, writing it to signature.
    ///
    /// `message_vec` is an iovec-like structure: the message is split across
    /// many buffers for digital signatures that are the concatenation of many
    /// parts, such as the Cerberus challenge command or a CWT signature.
    ///
    /// If the underlying cryptographic operation succeeds, returns `Ok(())`.
    /// Failures are included in the `Err` variant.
    fn sign(
        &mut self,
        message_vec: &[&[u8]],
        signature: &mut [u8],
    ) -> Result<(), Error>;
}

/// Public key parameters extracted from a certificate.
///
/// This must be paired with a compatible [`Algo`] (which specifies *algorithm*
/// parameters) to be usable for signature verification.
#[derive(Clone, Debug)]
pub enum PublicKeyParams<'cert> {
    /// Raw RSA parameters.
    Rsa {
        /// The key modulus, in big-endian.
        modulus: &'cert [u8],
        /// The key exponent, in big-endian.
        exponent: &'cert [u8],
    },
    /// A raw elliptic curve point.
    Ecc {
        /// The curve the point is from.
        curve: Curve,
        /// The x-coordinate, in big-endian.
        x: &'cert [u8],
        /// The y-coordinate, in big-endian.
        y: &'cert [u8],
    },
}

impl PublicKeyParams<'_> {
    /// Returns whether these parameters are appropriate for the given
    /// algorithm.
    pub fn is_params_for(&self, algo: Algo) -> bool {
        // Attributes are not allowed on expressions. We work around
        // this by putting it on a `let` instead.
        #[rustfmt::skip]
        let ok = matches!(
            (self, algo),
            (Self::Rsa { .. }, Algo::RsaPkcs1Sha256) |
            (Self::Ecc { curve: Curve::NistP256, .. }, Algo::EcdsaDerP256) |
            (Self::Ecc { curve: Curve::NistP256, .. }, Algo::EcdsaPkcs11P256)
        );
        ok
    }
}

/// An elliptic curve used in e.g. ECDSA.
///
/// See [`PublicKeyParams::Ecc`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Curve {
    NistP256,
}

/// A signature algorithm for a certificate subject key.
///
/// Each variant of this enum captures all parameters of the algorithm.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Algo {
    /// PKCS#1.5-encoded RSA signatures using SHA-256 for hashing.
    RsaPkcs1Sha256,
    /// DER-encoded ECDSA signatures using the NIST P-256 curve and
    /// SHA-256 for hashing.
    EcdsaDerP256,
    /// Fixed-width (PKCS#11-style) ECDSA signatures using the NIST
    /// P-256 curve and SHA-256 for hashing.
    EcdsaPkcs11P256,
}

/// A collection of ciphers that are provided to certificate machinery.
///
/// Users are expected to implement this trait to efficiently describe to
/// Manticore which algorithms they consider acceptable and how to access them.
pub trait Ciphers {
    /// Performs cryptographic capabilities negotiation.
    ///
    /// This function populates `caps` with whatever asymmetric cryptography
    /// it supports.
    fn negotiate(&self, caps: &mut capabilities::Crypto);

    /// Returns a [`Verify`] that can be used to verify signatures using
    /// the given `key`.
    ///
    /// Returns `None` if `key`'s algorithm is not supported.
    fn verifier<'a>(
        &'a mut self,
        algo: Algo,
        key: &PublicKeyParams,
    ) -> Option<&'a mut dyn Verify>;
}

/// A [`Ciphers`] that blindly accepts all signatures, for testing purposes.
#[cfg(test)]
pub(crate) struct NoVerify;

#[cfg(test)]
impl Verify for NoVerify {
    fn verify(&mut self, _: &[&[u8]], _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
impl Ciphers for NoVerify {
    fn negotiate(&self, _: &mut capabilities::Crypto) {}
    fn verifier<'a>(
        &'a mut self,
        _: Algo,
        _: &PublicKeyParams,
    ) -> Option<&'a mut dyn Verify> {
        Some(self)
    }
}
