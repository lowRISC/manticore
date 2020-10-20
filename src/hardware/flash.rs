// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! External, remote flash abstraction.
//!
//! This crate provides the [`Flash`] (and related) traits, which represent
//! *abstract flash devices*. An abstract flash device is a region of memory
//! that can be transactionally read or written. Such a "device" can range
//! from a simple Rust slice to a remote SPI flash device (or even a subregion of
//! it!).
//!
//! [`Flash`]: trait.Flash.html

use zerocopy::AsBytes;
use zerocopy::FromBytes;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Provides access to a flash-like storage device.
///
/// This trait provides abstract operations on a device, as if it were a
/// block of random-access memory. It is the implementation's responsibility
/// to implement these operations efficiently with respect to the underlying
/// device.
///
/// The `Flash` trait comes implemented for `[u8]`.
pub trait Flash {
    /// The error type returned by transactions with this `Flash`.
    type Error: Sized;

    /// Gets the size, in bytes, of this device.
    fn size(&self) -> Result<u32, Self::Error>;

    /// Attempt to read `slice` into `out`.
    ///
    /// If `out` is smaller than `slice.len`, only the first `out.len()` bytes
    /// will be read.
    fn read(
        &self,
        slice: FlashSlice,
        out: &mut [u8],
    ) -> Result<(), Self::Error>;
}

/// An abstract pointer into a [`Flash`] type.
///
/// A `FlashPtr` needs to be used in conjunction with a [`Flash`]
/// implementation to be read from or written to.
///
/// [`Flash`]: trait.Flash.html
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, AsBytes, FromBytes)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FlashPtr {
    /// The abstract address of this pointer.
    pub address: u32,
}

impl FlashPtr {
    /// Convenience method for creating a `FlashPtr` without having to use
    /// a struct literal.
    pub const fn new(address: u32) -> Self {
        Self { address }
    }
}

/// An abstrace slice into a [`Flash`] type.
///
/// Much like a [`FlashPtr`], a `FlashSlice` needs to be interpreted with
/// respect to a [`Flash`] implementation.
///
/// [`Flash`]: trait.Flash.html
/// [`FlashPtr`]: trait.FlashPtr.html
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, AsBytes, FromBytes)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FlashSlice {
    /// The base pointer for this slice.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub ptr: FlashPtr,
    /// The length of the slice, in bytes.
    pub len: u32,
}

impl FlashSlice {
    /// Convenience method for creating a `FlashSlice` without having to use
    /// a struct literal
    pub const fn new(ptr: u32, len: u32) -> Self {
        Self {
            ptr: FlashPtr::new(ptr),
            len,
        }
    }
}

/// An unspecified out-of-bounds error.
#[derive(Copy, Clone, Debug)]
pub struct OutOfBounds;

impl Flash for [u8] {
    type Error = OutOfBounds;

    fn size(&self) -> Result<u32, Self::Error> {
        Ok(self.len() as u32)
    }

    fn read(
        &self,
        slice: FlashSlice,
        out: &mut [u8],
    ) -> Result<(), Self::Error> {
        let start = slice.ptr.address as usize;
        let end = start + slice.len as usize;
        if start >= self.len() || end > self.len() {
            return Err(OutOfBounds);
        }
        out.copy_from_slice(&self[start..end]);
        Ok(())
    }
}
