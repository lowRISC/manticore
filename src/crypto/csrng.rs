// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic random numbers.

/// An error returned by a CSRNG.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Indicates an unspecified, internal error.
    Unspecified,
}

/// A cryptographically-secure random number generator.
///
/// The sole purpose of this type is to fill buffers with random bytes,
/// specifically for nonces or generating secrets as part of key exchange.
///
/// `Csrng`s must already be seeded with sufficient entropy; creating new
/// random number generators is beyond the scope of this trait.
pub trait Csrng {
    /// Fills `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}
impl dyn Csrng {} // Ensure object-safe.
