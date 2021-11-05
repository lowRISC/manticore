// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `DeviceInfo` request and response.
//!
//! This module provides a Cerberus command that allows the querying of
//! Cerberus and vendor-specified information about the device.

use crate::mem::ArenaExt as _;
use crate::protocol::CommandType;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

protocol_struct! {
    /// A command for requesting device information.
    type DeviceInfo;
    const TYPE: CommandType = DeviceInfo;

    struct Request {
        /// Which device information to look up.
        pub index: InfoIndex,
    }

    fn Request::from_wire(r, a) {
        let index = InfoIndex::from_wire(r, a)?;
        Ok(Self { index })
    }

    fn Request::to_wire(&self, w) {
        self.index.to_wire(&mut w)?;
        Ok(())
    }

    struct Response<'wire> {
        /// The requested information, in some binary format.
        ///
        /// The format of the response depends on which information index was sent.
        /// Only `0x00` is specified by Cerberus, which is reqired to produce the
        /// "Unique Chip Identifier".
        #[cfg_attr(feature = "serde", serde(
            serialize_with = "crate::serde::se_bytestring",
        ))]
        #[@static(cfg_attr(feature = "serde", serde(
            deserialize_with = "crate::serde::de_bytestring",
        )))]
        pub info: &'wire [u8],
    }

    fn Response::from_wire(r, arena) {
        let len = r.remaining_data();
        let buf = arena.alloc_slice::<u8>(len)?;
        r.read_bytes(buf)?;
        Ok(Self { info: buf })
    }

    fn Response::to_wire(&self, w) {
        w.write_bytes(self.info)?;
        Ok(())
    }
}

wire_enum! {
    /// A type of "device information" that can be requested.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum InfoIndex: u8 {
        /// Represents getting the Unique Chip Identifier for the device.
        UniqueChipIndex = 0x00,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x0],
            json: r#"{
                "index": "UniqueChipIndex"
            }"#,
            value: DeviceInfoRequest {
                index: InfoIndex::UniqueChipIndex,
            },
        },
        response_round_trip: {
            bytes: b"some unstructured data of no particular length",
            json: r#"{
                "info": "some unstructured data of no particular length"
            }"#,
            value: DeviceInfoResponse {
                info: b"some unstructured data of no particular length",
            },
        },
    }
}
