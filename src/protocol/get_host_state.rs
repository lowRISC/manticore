// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `GetHostState` request and response.
//!
//! This module provides a Cerberus command that allows the querying of
//! the reset state of the host processor protected by Cerberus.

use crate::io::Read;
use crate::io::Write;
use crate::mem::Arena;
use crate::protocol::wire::Error;
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

/// A command for requesting the host reset state
///
/// Corresponds to [`CommandType::GetHostState`].
pub enum GetHostState {}

impl<'a> Command<'a> for GetHostState {
    type Req = GetHostStateRequest;
    type Resp = GetHostStateResponse;
}

/// The [`GetHostState`] request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GetHostStateRequest {
    port_id: u8,
}
make_fuzz_safe!(GetHostStateRequest);

impl Request<'_> for GetHostStateRequest {
    const TYPE: CommandType = CommandType::GetHostState;
}

impl<'a> FromWire<'a> for GetHostStateRequest {
    fn from_wire<R: Read, A: Arena>(mut r: R, _: &'a A) -> Result<Self, Error> {
        let port_id = r.read_le()?;
        Ok(Self { port_id })
    }
}

impl<'a> ToWire for GetHostStateRequest {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), Error> {
        w.write_le(self.port_id)?;
        Ok(())
    }
}

make_fuzz_safe! {
    /// The [`GetHostState`] response.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct GetHostStateResponse as GHSWrap {
        host_reset_state: HostResetState,
    }
}

wire_enum! {
    /// Host processor reset state
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum HostResetState: u8 {
        /// Host is running (out of reset)
        HostRunning = 0x00,
        /// Host is being held in reset
        HostInReset = 0x01,
        /// Host is not being held in reset, but is not running
        HostNotRunning = 0x02,
    }
}

impl<'a> Response<'a> for GetHostStateResponse {
    const TYPE: CommandType = CommandType::GetHostState;
}

impl<'a> FromWire<'a> for GetHostStateResponse {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        arena: &'a A,
    ) -> Result<Self, Error> {
        let host_reset_state = HostResetState::from_wire(&mut r, arena)?;
        Ok(Self { host_reset_state })
    }
}

impl ToWire for GetHostStateResponse {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), Error> {
        self.host_reset_state.to_wire(&mut w)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x7f],
            value: GetHostStateRequest {
                port_id: 0x7f,
            },
        },
        response_round_trip: {
            bytes: &[0x01],
            value: GetHostStateResponse {
                host_reset_state: HostResetState::HostInReset,
            },
        },
    }
}