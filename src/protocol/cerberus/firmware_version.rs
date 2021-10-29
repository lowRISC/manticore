// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `FirmwareVersion` request and response.
//!
//! This module provides a Cerberus command allowing the versions of various
//! on-device firmware to be queried.

use crate::io::ReadInt as _;
use crate::mem::ArenaExt as _;
use crate::protocol::CommandType;

protocol_struct! {
    /// A command for requesting a firmware version.
    type FirmwareVersion;
    const TYPE: CommandType = FirmwareVersion;

    struct Request {
        /// Which portion of the RoT firmware to look up. `0` means the overall
        /// firmware image version. All other values are reserved for use by the
        /// integration.
        pub index: u8,
    }

    fn Request::from_wire(r, _) {
        let index = r.read_le()?;
        Ok(Self { index })
    }

    fn Request::to_wire(&self, w) {
        w.write_le(self.index)?;
        Ok(())
    }

    struct Response<'wire> {
        /// The firmware version. In practice, this is usually an ASCII string.
        #[cfg_attr(feature = "serde",
                   serde(deserialize_with = "crate::serde::de_u8_array_ref"))]
        #[cfg_attr(feature = "serde", serde(borrow))]
        pub version: &'wire [u8; 32],
    }

    fn Response::from_wire(r, arena) {
        let version: &mut [u8; 32] = arena.alloc::<[u8; 32]>()?;
        r.read_bytes(version)?;
        Ok(Self { version })
    }

    fn Response::to_wire(&self, w) {
        w.write_bytes(self.version)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const FIRMWARE_VERSION: &[u8; 32] = &[
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, //
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    ];

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x00],
            value: FirmwareVersionRequest { index: 0 },
        },
        request_round_trip2: {
            bytes: &[0x05],
            value: FirmwareVersionRequest { index: 5 },
        },
        response_round_trup: {
            bytes: FIRMWARE_VERSION,
            value: FirmwareVersionResponse { version: FIRMWARE_VERSION },
        },
    }
}
