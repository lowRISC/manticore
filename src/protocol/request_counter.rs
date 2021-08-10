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
use crate::io::ReadInt as _;
use crate::io::Write;
use crate::mem::Arena;
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

/// A command for querying the reqest counters.
///
/// Corresponds to [`CommandType::RequestCounter`].
pub enum RequestCounter {}

impl<'a> Command<'a> for RequestCounter {
    type Req = RequestCounterRequest;
    type Resp = RequestCounterResponse;
}

/// The [`RequestCounter`] request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RequestCounterRequest;
make_fuzz_safe!(RequestCounterRequest);

impl Request<'_> for RequestCounterRequest {
    const TYPE: CommandType = CommandType::RequestCounter;
}

impl<'a> FromWire<'a> for RequestCounterRequest {
    fn from_wire<R: Read, A: Arena>(
        _: R,
        _: &'a A,
    ) -> Result<Self, wire::Error> {
        Ok(RequestCounterRequest)
    }
}

impl<'a> ToWire for RequestCounterRequest {
    fn to_wire<W: Write>(&self, _: W) -> Result<(), wire::Error> {
        Ok(())
    }
}

/// The [`RequestCounter`] response.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RequestCounterResponse {
    /// The number of successful requests since reset.
    pub ok_count: u16,
    /// The number of failed requests since reset.
    pub err_count: u16,
}
make_fuzz_safe!(RequestCounterResponse);

impl Response<'_> for RequestCounterResponse {
    const TYPE: CommandType = CommandType::RequestCounter;
}

impl<'a> FromWire<'a> for RequestCounterResponse {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        _: &'a A,
    ) -> Result<Self, wire::Error> {
        let ok_count = r.read_le::<u16>()?;
        let err_count = r.read_le::<u16>()?;
        Ok(Self {
            ok_count,
            err_count,
        })
    }
}

impl ToWire for RequestCounterResponse {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
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
