// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `DeviceUptime` request and response.
//!
//! This module provides a Cerberus command allowing the host to query the
//! uptime of a component since it was powered on.
//!
//! Note that the command exposed by this module is a `manticore` extension.

use core::time::Duration;

use crate::io::ReadInt as _;
use crate::protocol::CommandType;

protocol_struct! {
    /// A command for requesting the time since reset.
    type DeviceUptime;
    const TYPE: CommandType = DeviceUptime;

    struct Request {
        /// The port of the device whose uptime is being looked up.
        #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
        pub port_id: u8,
    }

    fn Request::from_wire(r, _) {
        let port_id = r.read_le::<u8>()?;
        Ok(Self { port_id })
    }

    fn Request::to_wire(&self, w) {
        w.write_le(self.port_id)?;
        Ok(())
    }

    struct Response {
        /// The requested device uptime.
        ///
        /// Note that this value has microsecond accuracy in a range of four
        /// seconds.
        pub uptime: Duration,
    }

    fn Response::from_wire(r, _) {
        let micros = r.read_le::<u32>()?;
        let uptime = Duration::from_micros(micros as u64);
        Ok(Self { uptime })
    }

    fn Response::to_wire(&self, w) {
        let micros = self.uptime.as_micros() as u32;
        w.write_le(micros)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x0],
            json: r#"{
                "port_id": "0x00"
            }"#,
            value: DeviceUptimeRequest { port_id: 0 },
        },
        request_round_trip2: {
            bytes: &[0xaa],
            json: r#"{
                "port_id": "0xaa"
            }"#,
            value: DeviceUptimeRequest { port_id: 0xaa },
        },
        response_round_trip: {
            bytes: &5555u32.to_le_bytes(),
            json: r#"{
                "uptime": { "nanos": 5555000, "secs": 0 }
            }"#,
            value: DeviceUptimeResponse {
                uptime: Duration::from_micros(5555),
            },
        },
    }
}
