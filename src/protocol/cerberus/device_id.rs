// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `DeviceId` request and respose.
//!
//! This module provides a Cerberus command that allows requesting a unique
//! "device ID" from an RoT.

use crate::io::ReadInt as _;
use crate::io::ReadZero;
use crate::io::Write;
use crate::mem::Arena;
use crate::protocol::wire;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::ToWire;
use crate::protocol::CommandType;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};

#[cfg(doc)]
use crate::hardware::Identity;

protocol_struct! {
    /// A command for requesting a unique "device ID".
    type DeviceId;
    const TYPE: CommandType = DeviceId;

    struct Request {}

    fn Request::from_wire(_, _) {
        Ok(Self {})
    }

    fn Request::to_wire(&self, _w) {
        Ok(())
    }

    struct Response {
        /// A device identifier that uniquely identifies this device's silicon.
        pub id: DeviceIdentifier,
    }

    fn Response::from_wire(r, a) {
        let id = DeviceIdentifier::from_wire(r, a)?;
        Ok(Self { id })
    }

    fn Response::to_wire(&self, w) {
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// TODO: Remove this once we have a better idea of what Cerberus expects of
// these fields.
#[allow(missing_docs)]
pub struct DeviceIdentifier {
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
    pub vendor_id: u16,

    #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
    pub device_id: u16,

    #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
    pub subsys_vendor_id: u16,

    #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
    pub subsys_id: u16,
}

impl<'wire> FromWire<'wire> for DeviceIdentifier {
    fn from_wire<R: ReadZero<'wire> + ?Sized>(
        r: &mut R,
        _: &'wire dyn Arena,
    ) -> Result<Self, wire::Error> {
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
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
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
            json: "{}",
            value: DeviceIdRequest {},
        },
        response_round_trip: {
            bytes: b"abcdefgh",
            json: r#"{
                "id": {
                    "vendor_id": "0x6261",
                    "device_id": "0x6463",
                    "subsys_vendor_id": "0x6665",
                    "subsys_id": "0x6867"
                }
            }"#,
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
