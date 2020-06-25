// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `RequestCounter` request and response.
//!
//! This module provides a Cerberus command allowing the host to query the
//! number of requests this device has handled since reset.
//!
//! Note that the command exposed by this module is a `manticore` extension.

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

/// A command for querying the reqest counters.
///
/// Corresponds to [`CommandType::RequestCounter`].
///
/// [`CommandType::RequestCounter`]:
///     ../enum.CommandType.html#variant.RequestCounter
pub enum RequestCounter {}

impl<'a> Command<'a> for RequestCounter {
    type Req = RequestCounterRequest;
    type Resp = RequestCounterResponse;
}

/// The [`RequestCounter`] request.
///
/// [`RequestCounter`]: enum.RequestCounter.html
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
pub struct RequestCounterRequest;

impl Request<'_> for RequestCounterRequest {
    const TYPE: CommandType = CommandType::RequestCounter;
}

impl<'a> Deserialize<'a> for RequestCounterRequest {
    fn deserialize<R: Read<'a>>(_: &mut R) -> Result<Self, DeserializeError> {
        Ok(RequestCounterRequest)
    }
}

impl<'a> Serialize for RequestCounterRequest {
    fn serialize<W: Write>(&self, _: &mut W) -> Result<(), SerializeError> {
        Ok(())
    }
}

/// The [`RequestCounter`] response.
///
/// [`RequestCounter`]: enum.RequestCounter.html
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
pub struct RequestCounterResponse {
    /// The number of successful requests since reset.
    pub ok_count: u16,
    /// The number of failed requests since reset.
    pub err_count: u16,
}

impl Response<'_> for RequestCounterResponse {
    const TYPE: CommandType = CommandType::RequestCounter;
}

impl<'a> Deserialize<'a> for RequestCounterResponse {
    fn deserialize<R: Read<'a>>(r: &mut R) -> Result<Self, DeserializeError> {
        let ok_count = r.read_le::<u16>()?;
        let err_count = r.read_le::<u16>()?;
        Ok(Self {
            ok_count,
            err_count,
        })
    }
}

impl Serialize for RequestCounterResponse {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<(), SerializeError> {
        w.write_le(self.ok_count)?;
        w.write_le(self.err_count)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[],
            value: RequestCounterRequest,
        },
        response_round_trip: {
            bytes: &[0x44, 0x01, 0x07, 0x00],
            value: RequestCounterResponse {
                ok_count: 324,
                err_count: 7,
            },
        },
    }
}
