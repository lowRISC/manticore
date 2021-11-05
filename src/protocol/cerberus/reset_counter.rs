// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `ResetCounter` request and response.
//!
//! This module provides a Cerberus command allowing the host to query the
//! number of resets a device the RoT is connected to has undergone since it
//! powered on.

use crate::io::ReadInt as _;
use crate::protocol::CommandType;

protocol_struct! {
    /// A command for requesting the number of resets since power-on.
    type ResetCounter;
    const TYPE: CommandType = ResetCounter;

    struct Request {
        /// The type of counter being looked up.
        pub reset_type: ResetType,
        /// The port that the device whose reset counter is being looked up.
        #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
        pub port_id: u8,
    }

    fn Request::from_wire(r, a) {
        let reset_type = ResetType::from_wire(r, a)?;
        let port_id = r.read_le::<u8>()?;
        Ok(Self {
            reset_type,
            port_id,
        })
    }

    fn Request::to_wire(&self, w) {
        self.reset_type.to_wire(&mut w)?;
        w.write_le(self.port_id)?;
        Ok(())
    }

    struct Response {
        /// The number of resets since POR, for the requested device.
        pub count: u16,
    }

    fn Response::from_wire(r, _) {
        let count = r.read_le::<u16>()?;
        Ok(Self { count })
    }

    fn Response::to_wire(&self, w) {
        w.write_le(self.count)?;
        Ok(())
    }
}

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};

wire_enum! {
    /// A reset type, i.e., the kind of reset counter that is being queried.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub enum ResetType: u8 {
        /// A reset of the RoT handling the request.
        Local = 0x00,
        /// A reset of some external device connected to this RoT.
        ///
        /// This includes, for example, external flash devices, but not
        /// AC-RoTs challenged by this device.
        External = 0x01,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x01, 0x00],
            json: r#"{
                "reset_type": "External",
                "port_id": "0x00"
            }"#,
            value: ResetCounterRequest {
                reset_type: ResetType::External,
                port_id: 0
            },
        },
        request_round_trip2: {
            bytes: &[0x00, 0xaa],
            json: r#"{
                "reset_type": "Local",
                "port_id": "0xaa"
            }"#,
            value: ResetCounterRequest {
                reset_type: ResetType::Local,
                port_id: 0xaa
            },
        },
        response_round_trip: {
            bytes: &[0x20, 0x00],
            json: r#"{
                "count": 32
            }"#,
            value: ResetCounterResponse {
                count: 32
            },
        },
    }
}
