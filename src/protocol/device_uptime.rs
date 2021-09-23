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

use crate::io::ReadInt as _;
use crate::io::ReadZero;
use crate::io::Write;
use crate::mem::Arena;
use crate::protocol::wire;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::ToWire;
use crate::protocol::Command;
use crate::protocol::CommandType;
use crate::protocol::NoSpecificError;
use crate::protocol::Request;
use crate::protocol::Response;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(doc)]
use crate::hardware::Reset;

/// A command for requesting a firmware version.
///
/// Corresponds to [`CommandType::DeviceUptime`].
///
/// See [`Reset::uptime()`].
pub enum DeviceUptime {}

impl<'wire> Command<'wire> for DeviceUptime {
    type Req = DeviceUptimeRequest;
    type Resp = DeviceUptimeResponse;
    type Error = NoSpecificError;
}

/// The [`DeviceUptime`] request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceUptimeRequest {
    /// The port that the device whose uptime is being looked up.
    pub port_id: u8,
}
make_fuzz_safe!(DeviceUptimeRequest);

impl Request<'_> for DeviceUptimeRequest {
    const TYPE: CommandType = CommandType::DeviceUptime;
}

impl<'wire> FromWire<'wire> for DeviceUptimeRequest {
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        _: &'wire A,
    ) -> Result<Self, wire::Error> {
        let port_id = r.read_le::<u8>()?;
        Ok(Self { port_id })
    }
}

impl ToWire for DeviceUptimeRequest {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        w.write_le(self.port_id)?;
        Ok(())
    }
}

/// The [`DeviceUptime`] response.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceUptimeResponse {
    /// The requested device uptime.
    ///
    /// Note that this value has microsecond accuracy in a range of four
    /// seconds.
    pub uptime: Duration,
}
make_fuzz_safe!(DeviceUptimeResponse);

impl Response<'_> for DeviceUptimeResponse {
    const TYPE: CommandType = CommandType::DeviceUptime;
}

impl<'wire> FromWire<'wire> for DeviceUptimeResponse {
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        _: &'wire A,
    ) -> Result<Self, wire::Error> {
        let micros = r.read_le::<u32>()?;
        let uptime = Duration::from_micros(micros as u64);
        Ok(Self { uptime })
    }
}

impl ToWire for DeviceUptimeResponse {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        let micros = self.uptime.as_micros() as u32;
        w.write_le(micros)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x0],
            value: DeviceUptimeRequest { port_id: 0 },
        },
        request_round_trip2: {
            bytes: &[0xaa],
            value: DeviceUptimeRequest { port_id: 0xaa },
        },
        response_round_trip: {
            bytes: &5555u32.to_le_bytes(),
            value: DeviceUptimeResponse {
                uptime: Duration::from_micros(5555),
            },
        },
    }
}
