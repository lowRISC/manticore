// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Fakes for filling-in hardware functionality from `manticore::hardware`.

use std::collections::HashMap;
use std::convert::TryInto as _;
use std::time::Duration;
use std::time::Instant;

/// A fake `Identity` that returns fixed values.
pub struct Identity {
    firmware_version: Vec<u8>,
    vendor_firmware_versions: HashMap<u8, Vec<u8>>,
    unique_id: Vec<u8>,
}

impl Identity {
    /// Creates a new `Identity`.
    pub fn new<'a>(
        firmware_version: &[u8],
        vendor_firmware_versions: impl Iterator<Item = (u8, &'a [u8])>,
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
                .map(|(key, value)| (key, pad_to_32(value)))
                .collect(),
            unique_id: unique_id.to_vec(),
        }
    }
}

impl manticore::hardware::Identity for Identity {
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
    startup_time: Instant,
    resets_since_power_on: u32,
}

impl Reset {
    /// Creates a new `Reset`.
    pub fn new(resets_since_power_on: u32) -> Self {
        Self {
            startup_time: Instant::now(),
            resets_since_power_on,
        }
    }
}

impl manticore::hardware::Reset for Reset {
    fn resets_since_power_on(&self) -> u32 {
        self.resets_since_power_on
    }

    fn uptime(&self) -> Duration {
        self.startup_time.elapsed()
    }
}
