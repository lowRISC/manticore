// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `GetHostState` request and response.
//!
//! This module provides a Cerberus command that allows the querying of
//! the reset state of the host processor protected by Cerberus.

use crate::io::ReadInt as _;
use crate::protocol::cerberus::CommandType;

protocol_struct! {
    /// A command for requesting the host reset state.
    type GetHostState;
    const TYPE: CommandType = GetHostState;

    struct Request {
        /// The port that the device whose reset counter is being looked up.
        #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
        pub port_id: u8,
    }

    fn Request::from_wire(r, _) {
        let port_id = r.read_le()?;
        Ok(Self { port_id })
    }

    fn Request::to_wire(&self, w) {
        w.write_le(self.port_id)?;
        Ok(())
    }

    struct Response {
        /// The returned state.
        pub host_reset_state: HostResetState,
    }

    fn Response::from_wire(r, arena) {
        let host_reset_state = HostResetState::from_wire(r, arena)?;
        Ok(Self { host_reset_state })
    }

    fn Response::to_wire(&self, w) {
        self.host_reset_state.to_wire(&mut w)?;
        Ok(())
    }
}

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};

wire_enum! {
    /// Host processor reset state.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub enum HostResetState: u8 {
        /// Host is running (out of reset)
        HostRunning = 0x00,
        /// Host is being held in reset
        HostInReset = 0x01,
        /// Host is not being held in reset, but is not running
        HostNotRunning = 0x02,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x7f],
            json: r#"{
                "port_id": "0x7f"
            }"#,
            value: GetHostStateRequest {
                port_id: 0x7f,
            },
        },
        response_round_trip: {
            bytes: &[0x01],
            json: r#"{
                "host_reset_state": "HostInReset"
            }"#,
            value: GetHostStateResponse {
                host_reset_state: HostResetState::HostInReset,
            },
        },
    }
}
