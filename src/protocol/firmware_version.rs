// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `FirmwareVersion` request and response.
//!
//! This module provides a Cerberus command allowing the versions of various
//! on-device firmware to be queried.

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

/// A command for requesting a firmware version.
///
/// Corresponds to [`CommandType::FirmwareVersion`].
///
/// See [`hardware::Identity::firmware_version()`].
///
/// [`CommandType::FirmwareVersion`]:
///     ../enum.CommandType.html#variant.FirmwareVersion
/// [`hardware::Identity::firmware_version()`]:
///     ../../hardware/trait.Identity.html#tymethod.firmware_version
pub enum FirmwareVersion {}

impl<'a> Command<'a> for FirmwareVersion {
    type Req = FirmwareVersionRequest;
    type Resp = FirmwareVersionResponse<'a>;
}

/// The [`FirmwareVersion`] request.
///
/// [`FirmwareVersion`]: enum.FirmwareVersion.html
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FirmwareVersionRequest {
    /// Which portion of the RoT firmware to look up. `0` means the overall
    /// firmware image version. All other values are reserved for use by the
    /// integration.
    pub index: u8,
}

impl Request<'_> for FirmwareVersionRequest {
    const TYPE: CommandType = CommandType::FirmwareVersion;
}

impl<'a> Deserialize<'a> for FirmwareVersionRequest {
    fn deserialize<R: Read<'a>>(r: &mut R) -> Result<Self, DeserializeError> {
        let index = r.read_le()?;
        Ok(Self { index })
    }
}

impl<'a> Serialize for FirmwareVersionRequest {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<(), SerializeError> {
        w.write_le(self.index)?;
        Ok(())
    }
}

/// The [`FirmwareVersion`] response.
///
/// [`FirmwareVersion`]: enum.FirmwareVersion.html
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FirmwareVersionResponse<'a> {
    /// The firmware version, as an ASCII string.
    ///
    /// This string may be at most 32 characters long; longer strings will
    /// result in serialization errors, and shorter strings will be padded with
    /// NULs.
    pub version: &'a str,
}

impl<'a> Response<'a> for FirmwareVersionResponse<'a> {
    const TYPE: CommandType = CommandType::FirmwareVersion;
}

impl<'a> Deserialize<'a> for FirmwareVersionResponse<'a> {
    fn deserialize<R: Read<'a>>(r: &mut R) -> Result<Self, DeserializeError> {
        let version_bytes = r.read_bytes(32)?;
        let version = core::str::from_utf8(version_bytes)
            .map_err(|_| DeserializeError::OutOfRange)?;
        if !version.is_ascii() {
            return Err(DeserializeError::OutOfRange);
        }
        Ok(Self { version })
    }
}

impl Serialize for FirmwareVersionResponse<'_> {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<(), SerializeError> {
        let len = 32.min(self.version.len());
        let version = &self.version[..len];
        w.write_bytes(version.as_bytes())?;
        w.write_bytes(&[0; 32][len..])?;
        Ok(())
    }
}
