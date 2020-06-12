// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable hardware functionality
//!
//! This module provides traits for plugging in OS calls to specialized
//! hardware functions, such as power-on and reset-related capabilities.
//! `manticore` uses this functionality to respond to certain protocol
//! requests.

use core::time::Duration;

use zerocopy::AsBytes;
use zerocopy::FromBytes;

/// Provides access to "chip identity" information of various types.
pub trait Identity {
    /// Returns a string indicating the RoT's firmware version, in ASCII.
    ///
    /// This string should be ASCII and at most 32 bytes long, though callers
    /// should be robust against this contract not being upheld.
    fn firmware_version(&self) -> &str;

    /// Returns the "device identity" for the current device; this is a
    /// 64-bit integer of otherwise unspecified structure.
    fn device_identity(&self) -> u64;
}

/// Provides access to device reset-related information for a particular
/// device.
pub trait Reset {
    /// Returns the number of times the device has been reset since it was
    /// powered on.
    fn resets_since_power_on(&self) -> u32;

    /// Returns the uptime of the device, i.e., the absolute duration since it
    /// was last released from reset.
    ///
    /// The resolution and accuracy of this value are expected to be
    /// best-effort.
    fn uptime(&self) -> Duration;
}

/// Provides access to a flash-like storage device.
///
/// This trait provides abstract operations on a device, as if it were a
/// block of random-access memory. It is the implementation's responsibility
/// to implement these operations efficiently with respect to the underlying
/// device.
///
/// `Flash` is also implemented on main-memory `u8` buffers, which can be used
/// for testing.
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
#[derive(Copy, Clone, Debug, AsBytes, FromBytes)]
#[repr(transparent)]
pub struct FlashPtr {
    /// The abstract address of this pointer.
    pub address: u32,
}

/// An abstrace slice into a [`Flash`] type.
///
/// Much like a [`FlashPtr`], a `FlashSlice` needs to be interpreted with
/// respect to a [`Flash`] implementation.
///
/// [`Flash`]: trait.Flash.html
/// [`FlashPtr`]: trait.FlashPtr.html
#[derive(Copy, Clone, Debug, AsBytes, FromBytes)]
#[repr(C)]
pub struct FlashSlice {
    /// The base pointer for this slice.
    pub ptr: FlashPtr,
    /// The length of the slice, in bytes.
    pub len: u32,
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
