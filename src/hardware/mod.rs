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

pub mod flash;

/// Provides access to "chip identity" information of various types.
pub trait Identity {
    /// Returns a string indicating the RoT's firmware version.
    ///
    /// Although not enforced, it is recommended that this be an ASCII string.
    fn firmware_version(&self) -> &[u8; 32];

    /// Returns a string indicating the Vendor firmware version at the specified slot.
    fn vendor_firmware_version(&self, slot: u8) -> Option<&[u8; 32]> {
        let _ = slot;
        None
    }

    /// Returns the "unique device identity" for the device. This is a binary
    /// value of unspecified format.
    fn unique_device_identity(&self) -> &[u8];
}
impl dyn Identity {} // Ensure object-safe.

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
impl dyn Reset {} // Ensure object-safe.
