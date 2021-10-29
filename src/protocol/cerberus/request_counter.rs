// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `RequestCounter` request and response.
//!
//! This module provides a Cerberus command allowing the host to query the
//! number of requests this device has handled since reset.
//!
//! Note that the command exposed by this module is a `manticore` extension.

use crate::io::ReadInt as _;
use crate::protocol::CommandType;

protocol_struct! {
    /// A command for querying the request counters.
    type RequestCounter;
    const TYPE: CommandType = RequestCounter;

    struct Request {}

    fn Request::from_wire(_, _) {
        Ok(Self {})
    }

    fn Request::to_wire(&self, _w) {
        Ok(())
    }

    struct Response {
        /// The number of successful requests since reset.
        pub ok_count: u16,
        /// The number of failed requests since reset.
        pub err_count: u16,
    }

    fn Response::from_wire(r, _) {
        let ok_count = r.read_le::<u16>()?;
        let err_count = r.read_le::<u16>()?;
        Ok(Self {
            ok_count,
            err_count,
        })
    }

    fn Response::to_wire(&self, w) {
        w.write_le(self.ok_count)?;
        w.write_le(self.err_count)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[],
            value: RequestCounterRequest {},
        },
        response_round_trip: {
            bytes: &[0x44, 0x01, 0x07, 0x00],
            value: RequestCounterResponse {
                ok_count: 324,
                err_count: 7,
            },
        },
    }
}
