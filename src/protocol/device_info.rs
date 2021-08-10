// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `DeviceInfo` request and response.
//!
//! This module provides a Cerberus command that allows the querying of
//! Cerberus and vendor-specified information about the device.

use crate::io::ReadZero;
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

/// A command for requesting device information.
///
/// Corresponds to [`CommandType::DeviceInfo`].
pub enum DeviceInfo {}

impl<'wire> Command<'wire> for DeviceInfo {
    type Req = DeviceInfoRequest;
    type Resp = DeviceInfoResponse<'wire>;
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

/// The [`DeviceInfo`] request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceInfoRequest {
    /// Which device information to look up.
    pub index: InfoIndex,
}
make_fuzz_safe!(DeviceInfoRequest);

impl Request<'_> for DeviceInfoRequest {
    const TYPE: CommandType = CommandType::DeviceInfo;
}

impl<'wire> FromWire<'wire> for DeviceInfoRequest {
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        a: &'wire A,
    ) -> Result<Self, wire::Error> {
        let index = InfoIndex::from_wire(r, a)?;
        Ok(Self { index })
    }
}

impl ToWire for DeviceInfoRequest {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        self.index.to_wire(&mut w)?;
        Ok(())
    }
}

make_fuzz_safe! {
    /// The [`DeviceInfo`] response.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct DeviceInfoResponse<'wire> as DIRWrap {
        /// The requested information, in some binary format.
        ///
        /// The format of the response depends on which information index was sent.
        /// Only `0x00` is specified by Cerberus, which is reqired to produce the
        /// "Unique Chip Identifier".
        #[cfg_attr(feature = "serde", serde(borrow))]
        pub info: (&'wire [u8]),
    }
}

impl<'wire> Response<'wire> for DeviceInfoResponse<'wire> {
    const TYPE: CommandType = CommandType::DeviceInfo;
}

impl<'wire> FromWire<'wire> for DeviceInfoResponse<'wire> {
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        arena: &'wire A,
    ) -> Result<Self, wire::Error> {
        let len = r.remaining_data();
        let buf = arena.alloc_slice::<u8>(len)?;
        r.read_bytes(buf)?;
        Ok(Self { info: buf })
    }
}

impl ToWire for DeviceInfoResponse<'_> {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        w.write_bytes(self.info)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x0],
            value: DeviceInfoRequest {
                index: InfoIndex::UniqueChipIndex,
            },
        },
        response_round_trip: {
            bytes: b"some unstructured data of no particular length",
            value: DeviceInfoResponse {
                info: b"some unstructured data of no particular length",
            },
        },
    }
}
