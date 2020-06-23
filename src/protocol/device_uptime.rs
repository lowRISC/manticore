// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `DeviceUptime` request and response.
//!
//! This module provides a Cerberus command allowing the host to query the
//! uptime of a component since it was powered on.
//!
//! Note that the command exposed by this module is a `manticore` extension.

use core::time::Duration;

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

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};

/// A command for requesting a firmware version.
///
/// Corresponds to [`CommandType::DeviceUptime`].
///
/// See [`hardware::Reset::uptime()`].
///
/// [`CommandType::DeviceUptime`]:
///     ../enum.CommandType.html#variant.DeviceUptime
/// [`hardware::Reset::uptime()`]:
///     ../../hardware/trait.Reset.html#tymethod.uptime
pub enum DeviceUptime {}

impl<'a> Command<'a> for DeviceUptime {
    type Req = DeviceUptimeRequest;
    type Resp = DeviceUptimeResponse;
}

/// The [`DeviceUptime`] request.
///
/// [`DeviceUptime`]: enum.DeviceUptime.html
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
pub struct DeviceUptimeRequest {
    /// The port that the device whose uptime is being looked up.
    pub port_id: u8,
}

impl Request<'_> for DeviceUptimeRequest {
    const TYPE: CommandType = CommandType::DeviceUptime;
}

impl<'a> Deserialize<'a> for DeviceUptimeRequest {
    fn deserialize<R: Read<'a>>(r: &mut R) -> Result<Self, DeserializeError> {
        let port_id = r.read_le::<u8>()?;
        Ok(Self { port_id })
    }
}

impl<'a> Serialize for DeviceUptimeRequest {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<(), SerializeError> {
        w.write_le(self.port_id)?;
        Ok(())
    }
}

/// The [`DeviceUptime`] response.
///
/// [`DeviceUptime`]: enum.DeviceUptime.html
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
pub struct DeviceUptimeResponse {
    /// The requested device uptime.
    ///
    /// Note that this value has microsecond accuracy in a range of four
    /// seconds.
    pub uptime: Duration,
}

impl Response<'_> for DeviceUptimeResponse {
    const TYPE: CommandType = CommandType::DeviceUptime;
}

impl<'a> Deserialize<'a> for DeviceUptimeResponse {
    fn deserialize<R: Read<'a>>(r: &mut R) -> Result<Self, DeserializeError> {
        let micros = r.read_le::<u32>()?;
        let uptime = Duration::from_micros(micros as u64);
        Ok(Self { uptime })
    }
}

impl Serialize for DeviceUptimeResponse {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<(), SerializeError> {
        let micros = self.uptime.as_micros() as u32;
        w.write_le(micros)?;
        Ok(())
    }
}
