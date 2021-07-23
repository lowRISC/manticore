// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `DeviceId` request and respose.
//!
//! This module provides a Cerberus command that allows requesting a unique
//! "device ID" from an RoT.

use crate::io::Read;
use crate::io::Write;
use crate::mem::Arena;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::FromWireError;
use crate::protocol::wire::ToWire;
use crate::protocol::wire::ToWireError;
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

/// A command for requesting a unique "device ID".
///
/// Corresponds to [`CommandType::DeviceId`].
///
/// See [`Identity::unique_device_identity()`].
pub enum DeviceId {}

impl Command<'_> for DeviceId {
    type Req = DeviceIdRequest;
    type Resp = DeviceIdResponse;
}

/// The [`DeviceId`] request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceIdRequest;
make_fuzz_safe!(DeviceIdRequest);

impl Request<'_> for DeviceIdRequest {
    const TYPE: CommandType = CommandType::DeviceId;
}

impl<'a> FromWire<'a> for DeviceIdRequest {
    fn from_wire<R: Read, A: Arena>(
        _: R,
        _: &'a A,
    ) -> Result<Self, FromWireError> {
        Ok(DeviceIdRequest)
    }
}

impl ToWire for DeviceIdRequest {
    fn to_wire<W: Write>(&self, _: W) -> Result<(), ToWireError> {
        Ok(())
    }
}

/// The [`DeviceId`] response.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceIdResponse {
    /// A device identifier that uniquely identifies this device's silicon.
    pub id: DeviceIdentifier,
}
make_fuzz_safe!(DeviceIdResponse);

impl Response<'_> for DeviceIdResponse {
    const TYPE: CommandType = CommandType::DeviceId;
}

impl<'a> FromWire<'a> for DeviceIdResponse {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        a: &'a A,
    ) -> Result<Self, FromWireError> {
        let id = DeviceIdentifier::from_wire(&mut r, a)?;
        Ok(Self { id })
    }
}

impl ToWire for DeviceIdResponse {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), ToWireError> {
        self.id.to_wire(&mut w)?;
        Ok(())
    }
}

/// An identifier for a physical device.
///
/// This identifier is not of a secret nature, but mostly serves to allow
/// other devices on a Cerberus network to identify its make and model.
///
/// The meaning of the fields below is currently unspecified by Cerberus
/// beyond their names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
// TODO: Remove this once we have a better idea of what Cerberus expects of
// these fields.
#[allow(missing_docs)]
pub struct DeviceIdentifier {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsys_vendor_id: u16,
    pub subsys_id: u16,
}

impl<'a> FromWire<'a> for DeviceIdentifier {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        _: &'a A,
    ) -> Result<Self, FromWireError> {
        let vendor_id = r.read_le::<u16>()?;
        let device_id = r.read_le::<u16>()?;
        let subsys_vendor_id = r.read_le::<u16>()?;
        let subsys_id = r.read_le::<u16>()?;
        Ok(Self {
            vendor_id,
            device_id,
            subsys_vendor_id,
            subsys_id,
        })
    }
}

impl ToWire for DeviceIdentifier {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), ToWireError> {
        w.write_le(self.vendor_id)?;
        w.write_le(self.device_id)?;
        w.write_le(self.subsys_vendor_id)?;
        w.write_le(self.subsys_id)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[],
            value: DeviceIdRequest,
        },
        response_round_trip: {
            bytes: b"abcdefgh",
            value: DeviceIdResponse {
                id: DeviceIdentifier {
                    vendor_id: 0x6261,
                    device_id: 0x6463,
                    subsys_vendor_id: 0x6665,
                    subsys_id: 0x6867,
                }
            },
        },
    }
}
