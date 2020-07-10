// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `ResetCounter` request and response.
//!
//! This module provides a Cerberus command allowing the host to query the
//! number of resets a device the RoT is connected to has undergone since it
//! powered on.

use crate::io::Read;
use crate::io::Write;
use crate::protocol::Command;
use crate::protocol::CommandType;
use crate::protocol::FromWire;
use crate::protocol::FromWireError;
use crate::protocol::Request;
use crate::protocol::Response;
use crate::protocol::ToWire;
use crate::protocol::ToWireError;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};

/// A command for requesting a firmware version.
///
/// Corresponds to [`CommandType::ResetCounter`].
///
/// See [`hardware::Reset::resets_since_power_on()`].
///
/// [`CommandType::ResetCounter`]:
///     ../enum.CommandType.html#variant.ResetCounter
/// [`hardware::Reset::resets_since_power_on()`]:
///     ../../hardware/trait.Reset.html#tymethod.resets_since_power_on
pub enum ResetCounter {}

impl<'a> Command<'a> for ResetCounter {
    type Req = ResetCounterRequest;
    type Resp = ResetCounterResponse;
}

wire_enum! {
    /// A reset type, i.e., the kind of reset counter that is being queried.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
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

/// The [`ResetCounter`] request.
///
/// [`ResetCounter`]: enum.ResetCounter.html
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
pub struct ResetCounterRequest {
    /// The type of counter being looked up.
    pub reset_type: ResetType,
    /// The port that the device whose reset counter is being looked up.
    pub port_id: u8,
}

impl Request<'_> for ResetCounterRequest {
    const TYPE: CommandType = CommandType::ResetCounter;
}

impl<'a> FromWire<'a> for ResetCounterRequest {
    fn from_wire<R: Read<'a>>(r: &mut R) -> Result<Self, FromWireError> {
        let reset_type = ResetType::from_wire(r)?;
        let port_id = r.read_le::<u8>()?;
        Ok(Self {
            reset_type,
            port_id,
        })
    }
}

impl<'a> ToWire for ResetCounterRequest {
    fn to_wire<W: Write>(&self, w: &mut W) -> Result<(), ToWireError> {
        self.reset_type.to_wire(w)?;
        w.write_le(self.port_id)?;
        Ok(())
    }
}

/// The [`ResetCounter`] response.
///
/// [`ResetCounter`]: enum.ResetCounter.html
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
pub struct ResetCounterResponse {
    /// The number of resets since POR, for the requested device.
    pub count: u16,
}

impl Response<'_> for ResetCounterResponse {
    const TYPE: CommandType = CommandType::ResetCounter;
}

impl<'a> FromWire<'a> for ResetCounterResponse {
    fn from_wire<R: Read<'a>>(r: &mut R) -> Result<Self, FromWireError> {
        let count = r.read_le::<u16>()?;
        Ok(Self { count })
    }
}

impl ToWire for ResetCounterResponse {
    fn to_wire<W: Write>(&self, w: &mut W) -> Result<(), ToWireError> {
        w.write_le(self.count)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x01, 0x00],
            value: ResetCounterRequest {
                reset_type: ResetType::External,
                port_id: 0
            },
        },
        request_round_trip2: {
            bytes: &[0x00, 0xaa],
            value: ResetCounterRequest {
                reset_type: ResetType::Local,
                port_id: 0xaa
            },
        },
        response_round_trip: {
            bytes: &[0x20, 0x00],
            value: ResetCounterResponse {
                count: 32
            },
        },
    }
}
