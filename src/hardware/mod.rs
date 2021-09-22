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

#[cfg(test)]
pub(crate) mod fake {
    use core::convert::TryInto;
    use core::time::Duration;
    use std::collections::HashMap;

    /// A fake `Identity` that returns fixed values.
    pub struct Identity {
        firmware_version: Vec<u8>,
        vendor_firmware_versions: HashMap<u8, Vec<u8>>,
        unique_id: Vec<u8>,
    }

    impl Identity {
        /// Creates a new `fake::Identity`.
        pub fn new(
            firmware_version: &[u8],
            vendor_firmware_versions: &[(u8, &[u8])],
            unique_id: &[u8],
        ) -> Self {
            fn pad_to_32(data: &[u8]) -> Vec<u8> {
                let mut vec = data.to_vec();
                while vec.len() < 32 {
                    vec.push(0);
                }
                vec.truncate(32);

                vec
            }

            Self {
                firmware_version: pad_to_32(firmware_version),
                vendor_firmware_versions: vendor_firmware_versions
                    .iter()
                    .map(|(key, value)| (*key, pad_to_32(value)))
                    .collect(),
                unique_id: unique_id.to_vec(),
            }
        }
    }

    impl super::Identity for Identity {
        fn firmware_version(&self) -> &[u8; 32] {
            self.firmware_version[..32].try_into().unwrap()
        }
        fn vendor_firmware_version(&self, slot: u8) -> Option<&[u8; 32]> {
            self.vendor_firmware_versions
                .get(&slot)
                .map(|data| data[..32].try_into().unwrap())
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
