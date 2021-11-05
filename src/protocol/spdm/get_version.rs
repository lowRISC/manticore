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
        pub versions: &'wire [Version],
    }

    fn Response::from_wire(r, arena) {
        spdm::expect_zeros(r, 3)?;

        let count = r.read_le::<u8>()?;
        let versions = r.read_slice::<Version>(count as usize, arena)?;
        Ok(Self { versions })
    }

    fn Response::to_wire(&self, w) {
        spdm::write_zeros(&mut w, 3)?;
        w.write_le::<u8>(self.versions.len().try_into().map_err(|_| wire::Error::OutOfRange)?)?;
        w.write_bytes(self.versions.as_bytes())?;
        Ok(())
    }
}

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};

/// An SPDM protocol version.
///
/// A version consists of four nybbles: major, minor, revision, alpha.
#[derive(
    Clone, Copy, PartialEq, Eq, Debug, zerocopy::FromBytes, zerocopy::AsBytes,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[repr(transparent)]
pub struct Version {
    version: [u8; 2],
}
derive_borrowed!(Version);

impl Version {
    /// The version of SPDM Manticore implements.
    pub const MANTICORE: Version = Version::new(1, 2, 0, 0);

    /// Constructs a new `version`.
    ///
    /// Although parameters are given as bytes, only their low nybbles are used.
    pub const fn new(major: u8, minor: u8, revision: u8, alpha: u8) -> Self {
        Self {
            version: [
                revision << 4 | (alpha & 0xf),
                major << 4 | (minor & 0xf),
            ],
        }
    }

    /// Extracts the major version.
    pub const fn major(self) -> u8 {
        self.version[1] >> 4
    }

    /// Extracts the minor version.
    pub const fn minor(self) -> u8 {
        self.version[0] & 0xf
    }

    /// Extracts the version revision.
    pub const fn revision(self) -> u8 {
        self.version[0] >> 4
    }

    /// Extracts the alpha value.
    pub const fn alpha(self) -> u8 {
        self.version[0] & 0xf
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
                "versions": [[0, 18]]
            }"#,
            value: GetVersionResponse { versions: &[Version::MANTICORE] },
        },
    }
}
