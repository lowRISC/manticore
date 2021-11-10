// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `GetVersion` request and response.
//!
//! This module provides an SPDM command for negotiating the protocol version.

use core::convert::TryInto as _;

use zerocopy::AsBytes as _;

use crate::io::read::ReadZeroExt as _;
use crate::io::ReadInt as _;
use crate::protocol::spdm;
use crate::protocol::spdm::CommandType;
use crate::protocol::spdm::ExtendedVersion;

protocol_struct! {
    /// A command for requestion a protocol version.
    type GetVersion;
    const TYPE: CommandType = GetVersion;

    struct Request {}

    fn Request::from_wire(r, _) {
        spdm::expect_zeros(r, 2)?;
        Ok(Self {})
    }

    fn Request::to_wire(&self, w) {
        spdm::write_zeros(&mut w, 2)
    }

    struct Response<'wire> {
        /// The set of versions supported.
        pub versions: &'wire [ExtendedVersion],
    }

    fn Response::from_wire(r, arena) {
        spdm::expect_zeros(r, 3)?;

        let count = r.read_le::<u8>()?;
        let versions = r.read_slice::<ExtendedVersion>(count as usize, arena)?;
        Ok(Self { versions })
    }

    fn Response::to_wire(&self, w) {
        spdm::write_zeros(&mut w, 3)?;
        w.write_le::<u8>(self.versions.len().try_into().map_err(|_| wire::Error::OutOfRange)?)?;
        w.write_bytes(self.versions.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x00, 0x00],
            json: "{}",
            value: GetVersionRequest {},
        },
        response_round_trup: {
            bytes: &[0x00, 0x00, 0x00, 0x01, 0x00, 0x12],
            json: r#"{
                "versions": [{ "version": "0x12" }]
            }"#,
            value: GetVersionResponse { versions: &[ExtendedVersion::MANTICORE] },
        },
    }
}
