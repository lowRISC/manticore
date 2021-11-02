// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic hashing, including HMAC construction.
//!
//! In general, users of this module should be pulling in [`EngineExt`],
//! adds functions to [`Engine`] for more ergonomic usage, but which would
//! otherwise make it object-unsafe.

use crate::mem::Arena;
use crate::mem::ArenaExt as _;
use crate::mem::OutOfMemory;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};

/// A cryptographic hashing algorithm.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
pub enum Algo {
    /// 256-bit SHA-2.
    Sha256,
    /// 384-bit SHA-2.
    Sha384,
    /// 512-bit SHA-2.
    Sha512,
}
derive_borrowed!(Algo);

impl Algo {
    /// The number of bits in a digest or HMAC of this strength.
    #[inline]
    pub const fn bits(self) -> usize {
        match self {
            Self::Sha256 => 256,
            Self::Sha384 => 384,
            Self::Sha512 => 512,
        }
    }

    /// The number of bytes in a digest or HMAC of this strength.
    #[inline]
    pub const fn bytes(self) -> usize {
        self.bits() / 8
    }

    /// Allocates sufficient storage from `arena` to hold a hash of this type.
    #[inline]
    pub fn alloc(self, arena: &impl Arena) -> Result<&mut [u8], OutOfMemory> {
        arena.alloc_slice(self.bytes())
    }
}

/// An error returned by a hashing function.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Indicates that the wrong size of digest was provided to
    /// [`Engine::finish_raw()`].
    WrongSize,

    /// Indicates that the engine was idle, but a write or finish
    /// operation was requested.
    Idle,

    /// Indicates an unspecified, internal error.
    Unspecified,
}

/// A hashing engine, which maintains the state for one digest.
///
/// Callers should not use the `raw` API directly; [`Hasher`] is a type-safe
/// wrapper that manages a session with an `Engine`.
///
/// Implementers only need to provide the "raw" form of the API; the remaining
/// functions are convenience helpers.
pub trait Engine {
    /// Returns whether this engine supports the given algorithm.
    fn supports(&mut self, algo: Algo) -> bool;

    /// Begins a new hashing operation, discarding any previous state.
    ///
    /// If `key` is `Some`, this becomes an HMAC operation instead, using that
    /// as the key.
    fn start_raw(
        &mut self,
        algo: Algo,
        key: Option<&[u8]>,
    ) -> Result<(), Error>;

    /// Adds `data` to the hashing state.
    fn write_raw(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Completes the hashing/HMAC operation.
    ///
    /// Calling this function multiple times will have an unspecified effect.
    fn finish_raw(&mut self, out: &mut [u8]) -> Result<(), Error>;

    /// Completes the hashing/HMAC operation, and then  compares it to `expected`.
    ///
    /// Returns `Ok(())` if the hashes matched.
    ///
    /// Calling this function multiple times will have an unspecified effect.
    fn compare_raw(&mut self, expected: &[u8]) -> Result<(), Error>;
}

/// Helpers for creating a [`Hasher`] from an [`Engine`].
#[extend::ext(name = EngineExt)]
pub impl<E: Engine + ?Sized> E {
    /// Begins a new hashing operation.
    ///
    /// Implementers do not need to implement this function themselves.
    #[inline]
    fn new_hash(&mut self, algo: Algo) -> Result<Hasher<&mut Self>, Error> {
        self.start_raw(algo, None)?;
        Ok(Hasher { engine: self })
    }

    /// Begins a new HMAC operation, using the given secret key.
    ///
    /// Implementers do not need to implement this function themselves.
    #[inline]
    fn new_hmac(
        &mut self,
        algo: Algo,
        key: &[u8],
    ) -> Result<Hasher<&mut Self>, Error> {
        self.start_raw(algo, Some(key))?;
        Ok(Hasher { engine: self })
    }

    /// Convenience helper for hashing a contiguous memory region.
    ///
    /// Implementers do not need to implement this function themselves.
    #[inline]
    fn contiguous_hash(
        &mut self,
        algo: Algo,
        buf: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut h = self.new_hash(algo)?;
        h.write(buf)?;
        h.finish(out)
    }

    /// Convenience helper for HMAC'ing a contiguous memory region.
    ///
    /// Implementers do not need to implement this function themselves.
    #[inline]
    fn contiguous_hmac(
        &mut self,
        algo: Algo,
        key: &[u8],
        buf: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut h = self.new_hmac(algo, key)?;
        h.write(buf)?;
        h.finish(out)
    }
}

// Ensure Engine is object-safe.
impl dyn Engine {}

/// A helper for managing a hashing operation with an [`Engine`].
///
/// Users should prefer to use this instead of calling [`Engine`]'s raw API
/// directly.
pub struct Hasher<E> {
    engine: E,
}

impl<E: Engine + ?Sized> Hasher<&mut E> {
    /// Adds `data` to the hashing state.
    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.engine.write_raw(data)
    }

    /// Completes the hashing/HMAC operation, writing the result to `out`.
    pub fn finish(self, out: &mut [u8]) -> Result<(), Error> {
        self.engine.finish_raw(out)
    }

    /// Completes the hashing/HMAC operation, comparing the result to `expected`.
    pub fn expect(self, expected: &[u8]) -> Result<(), Error> {
        self.engine.compare_raw(expected)
    }
}
