// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Algorithm-generic signature traits.

/// An error returned by a signature operation.
///
/// This type serves as a combination of built-in error types known to
/// Manticore, plus a "custom error" component for surfacing
/// implementation-specific errors that Manticore can treat as a black box.
///
/// This type has the benefit that, unlike a pure associated type, `From`
/// implementations for error-handling can be implemented on it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error<E = ()> {
    /// The "custom" error type, which is treated by Manticore as a black box.
    Custom(E),
}

impl<E> Error<E> {
    /// Erases the custom error type from this `Error`, replacing it with `()`.
    pub fn erased(self) -> Error {
        match self {
            Self::Custom(_) => Error::Custom(()),
        }
    }
}

/// Convenience type for the error returned by [`Verify::verify()`].
pub type VerifyError<V> = Error<<V as Verify>::Error>;

/// Convenience type for the error returned by [`Sign::sign()`].
pub type SignError<S> = Error<<S as Sign>::Error>;

/// A signature-verification engine, already primed with a key.
///
/// There is no way to extract the key back out of a `Verify` value.
pub trait Verify {
    /// The error returned when an operation fails.
    type Error;

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
    ) -> Result<(), VerifyError<Self>>;
}

/// Marker trait for specifying a bound on a [`Verify`] to specify that it can
/// verify a specific kind of signature.
///
/// For example, you might write `verify: impl VerifyFor<Rsa>` instead of
/// `verify: impl Verify` if you only wish to accept verifiers for RSA. This is
/// mostly useful in situations where this is the only supported algorithm for
/// an operation.
pub trait VerifyFor<Algo>: Verify {}

/// An signing engine, already primed with a keypair.
///
/// There is no way to extract the keypair back out of a `Sign` value.
pub trait Sign {
    /// The error returned when an operation fails.
    type Error;

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
    ) -> Result<(), SignError<Self>>;
}

/// Marker trait for specifying a bound on a [`Sign`] to specify that it can
/// create a specific kind of signature.
///
/// See [`VerifyFor`].
pub trait SignFor<Algo>: Sign {}

/// Public key parameters extracted from a certificate.
///
/// This must be paired with a compatible [`Algo`] (which specifies *algorithm*
/// parameters) to be usable for signature verification.
#[derive(Debug)]
pub enum PublicKeyParams<'cert> {
    /// RSA in an unspecified form with an unspecified hash function.
    Rsa {
        /// The key modulus, in big-endian.
        modulus: &'cert [u8],
        /// The key exponent, in big-endian.
        exponent: &'cert [u8],
    },
}

impl PublicKeyParams<'_> {
    /// Returns whether these parameters are appropriate for the given
    /// algorithm.
    pub fn is_params_for(&self, algo: Algo) -> bool {
        match (self, algo) {
            (Self::Rsa { .. }, Algo::RsaPkcs1Sha256) => true,
        }
    }
}

/// A signature algorithm for a certificate subject key.
///
/// Each variant of this enum captures all parameters of the algorithm.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Algo {
    /// PKCS#1.5-encoded RSA signatures using SHA-256 for hashing.
    RsaPkcs1Sha256,
}

/// A collection of ciphers that are provided to certificate machinery.
///
/// Users are expected to implement this trait to efficiently describe to
/// Manticore which algorithms they consider acceptable and how to access them.
pub trait Ciphers {
    /// The error returned by verifiers on failure.
    type Error;

    /// Returns a [`Verify`] that can be used to verify signatures using
    /// the given `key`.
    ///
    /// Returns `None` if `key`'s algorithm is not supported.
    fn verifier<'a>(
        &'a mut self,
        algo: Algo,
        key: &PublicKeyParams,
    ) -> Option<&'a mut dyn Verify<Error = Self::Error>>;
}

/// A [`Ciphers`] that blindly accepts all signatures, for testing purposes.
#[cfg(test)]
pub(crate) struct NoVerify;

#[cfg(test)]
impl Verify for NoVerify {
    type Error = ();
    fn verify(
        &mut self,
        _: &[&[u8]],
        _: &[u8],
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
impl Ciphers for NoVerify {
    type Error = ();
    fn verifier<'a>(
        &'a mut self,
        _: Algo,
        _: &PublicKeyParams,
    ) -> Option<&'a mut dyn Verify<Error = ()>> {
        Some(self)
    }
}
