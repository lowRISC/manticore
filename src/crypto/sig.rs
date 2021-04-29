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
/// There is no way to extract the key back out of an `Engine` value.
pub trait Verify {
    /// The error returned when an operation fails.
    type Error;

    /// Uses this engine to verify `signature` against `expected_hash`, by
    /// performing an encryption operation on `signature`, and comparing the
    /// result to a hash of `message`.
    ///
    /// If the underlying cryptographic operation succeeds, returns `Ok(())`.
    /// Failures, including signature check failures, are included in the
    /// `Err` variant.
    fn verify(
        &mut self,
        signature: &[u8],
        message: &[u8],
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

    /// Uses this signer to create a signature value for `message`.
    ///
    /// If the underlying cryptographic operation succeeds, returns `Ok(())`.
    /// Failures are included in the `Err` variant.
    fn sign(
        &mut self,
        message: &[u8],
        signature: &mut [u8],
    ) -> Result<(), SignError<Self>>;
}

/// Marker trait for specifying a bound on a [`Sign`] to specify that it can
/// create a specific kind of signature.
///
/// See [`VerifyFor`].
pub trait SignFor<Algo>: Sign {}
