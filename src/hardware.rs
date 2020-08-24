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

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Provides access to "chip identity" information of various types.
pub trait Identity {
    /// Returns a string indicating the RoT's firmware version.
    ///
    /// Although not enforced, it is recommended that this be an ASCII string.
    fn firmware_version(&self) -> &[u8; 32];

    /// Returns the "unique device identity" for the device. This is a binary
    /// value of unspecified format.
    fn unique_device_identity(&self) -> &[u8];
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, AsBytes, FromBytes)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FlashPtr {
    /// The abstract address of this pointer.
    pub address: u32,
}

impl FlashPtr {
    /// Convenience method for creating a `FlashPtr` without having to use
    /// a struct literal
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

#[cfg(test)]
pub(crate) mod fake {
    use core::convert::TryInto;
    use core::time::Duration;

    /// A fake `Identity` that returns fixed values.
    pub struct Identity {
        firmware_version: Vec<u8>,
        unique_id: Vec<u8>,
    }

    impl Identity {
        /// Creates a new `fake::Identity`.
        pub fn new(firmware_version: &[u8], unique_id: &[u8]) -> Self {
            let mut firmware_version = firmware_version.to_vec();
            while firmware_version.len() < 32 {
                firmware_version.push(0);
            }
            firmware_version.truncate(32);

            Self {
                firmware_version,
                unique_id: unique_id.to_vec(),
            }
        }
    }

    impl super::Identity for Identity {
        fn firmware_version(&self) -> &[u8; 32] {
            self.firmware_version[..32].try_into().unwrap()
        }
        fn unique_device_identity(&self) -> &[u8] {
            &self.unique_id[..]
        }
    }

    /// A fake `Reset` that returns fixed values.
    pub struct Reset {
        resets: u32,
        uptime: Duration,
    }

    impl Reset {
        /// Creates a new `fake::Reset`.
        pub fn new(resets: u32, uptime: Duration) -> Self {
            Self { resets, uptime }
        }
    }

    impl super::Reset for Reset {
        fn resets_since_power_on(&self) -> u32 {
            self.resets
        }

        fn uptime(&self) -> Duration {
            self.uptime
        }
    }
}
