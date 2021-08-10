// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `FirmwareVersion` request and response.
//!
//! This module provides a Cerberus command allowing the versions of various
//! on-device firmware to be queried.

use crate::io::Read;
use crate::io::ReadInt as _;
use crate::io::Write;
use crate::mem::Arena;
use crate::mem::ArenaExt as _;
use crate::protocol::wire;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::ToWire;
use crate::protocol::Command;
use crate::protocol::CommandType;
use crate::protocol::Request;
use crate::protocol::Response;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(doc)]
use crate::hardware::Identity;

/// A command for requesting a firmware version.
///
/// Corresponds to [`CommandType::FirmwareVersion`].
///
/// See [`Identity::firmware_version()`].
pub enum FirmwareVersion {}

impl<'a> Command<'a> for FirmwareVersion {
    type Req = FirmwareVersionRequest;
    type Resp = FirmwareVersionResponse<'a>;
}

/// The [`FirmwareVersion`] request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FirmwareVersionRequest {
    /// Which portion of the RoT firmware to look up. `0` means the overall
    /// firmware image version. All other values are reserved for use by the
    /// integration.
    pub index: u8,
}
make_fuzz_safe!(FirmwareVersionRequest);

impl Request<'_> for FirmwareVersionRequest {
    const TYPE: CommandType = CommandType::FirmwareVersion;
}

impl<'a> FromWire<'a> for FirmwareVersionRequest {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        _: &'a A,
    ) -> Result<Self, wire::Error> {
        let index = r.read_le()?;
        Ok(Self { index })
    }
}

impl<'a> ToWire for FirmwareVersionRequest {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        w.write_le(self.index)?;
        Ok(())
    }
}

make_fuzz_safe! {
    /// The [`FirmwareVersion`] response.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct FirmwareVersionResponse<'a> as FVRWrap {
        /// The firmware version. In practice, this is usually an ASCII string.
        #[cfg_attr(feature = "serde",
                   serde(deserialize_with = "crate::serde::de_u8_array_ref"))]
        #[cfg_attr(feature = "serde", serde(borrow))]
        pub version: (&'a [u8; 32]),
    }
}

impl<'a> Response<'a> for FirmwareVersionResponse<'a> {
    const TYPE: CommandType = CommandType::FirmwareVersion;
}

impl<'a> FromWire<'a> for FirmwareVersionResponse<'a> {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        arena: &'a A,
    ) -> Result<Self, wire::Error> {
        let version: &mut [u8; 32] = arena.alloc::<[u8; 32]>()?;
        r.read_bytes(version)?;
        Ok(Self { version })
    }
}

impl ToWire for FirmwareVersionResponse<'_> {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
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
