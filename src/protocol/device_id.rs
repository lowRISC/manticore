// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `DeviceId` request and respose.
//!
//! This module provides a Cerberus command that allows requesting a unique
//! "device ID" from an RoT.

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

/// A command for requesting a unique "device ID".
///
/// Corresponds to [`CommandType::DeviceId`].
///
/// See [`hardware::Identity::device_identity()`].
///
/// [`CommandType::DeviceId`]:
///     ../enum.CommandType.html#variant.DeviceId
/// [`hardware::Identity::device_identity()`]:
///     ../../hardware/trait.Identity.html#tymethod.device_identity
pub enum DeviceId {}

impl Command<'_> for DeviceId {
    type Req = DeviceIdRequest;
    type Resp = DeviceIdResponse;
}

/// The [`DeviceId`] request.
///
/// [`DeviceId`]: enum.DeviceId.html
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceIdRequest;

impl Request<'_> for DeviceIdRequest {
    const TYPE: CommandType = CommandType::DeviceId;
}

impl<'a> Deserialize<'a> for DeviceIdRequest {
    fn deserialize<R: Read<'a>>(_: &mut R) -> Result<Self, DeserializeError> {
        Ok(DeviceIdRequest)
    }
}

impl Serialize for DeviceIdRequest {
    fn serialize<W: Write>(&self, _: &mut W) -> Result<(), SerializeError> {
        Ok(())
    }
}

/// The [`DeviceId`] response.
///
/// [`DeviceId`]: enum.DeviceId.html
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceIdResponse {
    /// A "device id".
    ///
    /// Currently, this is an unstructured collection of 64 bits.
    pub id: u64,
}

impl Response<'_> for DeviceIdResponse {
    const TYPE: CommandType = CommandType::DeviceId;
}

impl<'a> Deserialize<'a> for DeviceIdResponse {
    fn deserialize<R: Read<'a>>(r: &mut R) -> Result<Self, DeserializeError> {
        let id = r.read_le()?;
        Ok(Self { id })
    }
}

impl Serialize for DeviceIdResponse {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<(), SerializeError> {
        w.write_le(self.id)?;
        Ok(())
    }
}
