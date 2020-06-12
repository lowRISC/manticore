// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `DeviceInfo` request and response.
//!
//! This module provides a Cerberus command that allows the querying of
//! Cerberus and vendor-specified information about the device.

use crate::io::Read;
use crate::io::Write;
use crate::protocol::Command;
use crate::protocol::CommandType;
use crate::protocol::Deserialize;
use crate::protocol::DeserializeError;
use crate::protocol::Request;
use crate::protocol::Response;
use crate::protocol::Serialize;
use crate::protocol::SerializeError;

/// A command for requesting device information.
///
/// Corresponds to [`CommandType::DeviceInfo`].
///
/// [`CommandType::DeviceInfo`]:
///     ../enum.CommandType.html#variant.DeviceInfo
pub enum DeviceInfo {}

impl<'a> Command<'a> for DeviceInfo {
    type Req = DeviceInfoRequest;
    type Resp = DeviceInfoResponse<'a>;
}

wire_enum! {
    /// A type of "device information" that can be requested.
    pub enum InfoIndex: u8 {
        /// Represents getting the Unique Chip Identifier for the device.
        UniqueChipIndex = 0x00,
    }
}

/// The [`DeviceInfo`] request.
///
/// [`DeviceInfo`]: enum.DeviceInfo.html
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfoRequest {
    /// Which device information to look up.
    pub index: InfoIndex,
}

impl Request<'_> for DeviceInfoRequest {
    const TYPE: CommandType = CommandType::DeviceInfo;
}

impl<'a> Deserialize<'a> for DeviceInfoRequest {
    fn deserialize<R: Read<'a>>(r: &mut R) -> Result<Self, DeserializeError> {
        let index = InfoIndex::deserialize(r)?;
        Ok(Self { index })
    }
}

impl<'a> Serialize for DeviceInfoRequest {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<(), SerializeError> {
        self.index.serialize(w)?;
        Ok(())
    }
}

/// The [`DeviceInfo`] response.
///
/// [`DeviceInfo`]: enum.DeviceInfo.html
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfoResponse<'a> {
    /// The requested information, in some binary format.
    ///
    /// The format of the response depends on which information index was sent.
    /// Only `0x00` is specified by Cerberus, which is reqired to produce the
    /// "Unique Chip Identifier".
    pub info: &'a [u8],
}

impl<'a> Response<'a> for DeviceInfoResponse<'a> {
    const TYPE: CommandType = CommandType::DeviceInfo;
}

impl<'a> Deserialize<'a> for DeviceInfoResponse<'a> {
    fn deserialize<R: Read<'a>>(r: &mut R) -> Result<Self, DeserializeError> {
        let len = r.remaining_data();
        let info = r.read_bytes(len)?;
        Ok(Self { info })
    }
}

impl Serialize for DeviceInfoResponse<'_> {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<(), SerializeError> {
        w.write_bytes(self.info)?;
        Ok(())
    }
}
