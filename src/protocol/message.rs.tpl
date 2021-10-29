// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `{command}` request and response.
//!
//! This module provides a Cerberus command for TODO

use crate::io::ReadInt as _;
use crate::mem::ArenaExt as _;
use crate::protocol::CommandType;

protocol_struct! {
    /// A command for TODO
    type {command};
    const TYPE: CommandType = {command};

    struct Request<'wire> {
        // TODO
    }

    fn Request::from_wire(r, arena) {
        // TODO
    }

    fn Request::to_wire(&self, w) {
        // TODO
    }

    struct Response<'wire> {
        // TODO
    }

    fn Response::from_wire(r, arena) {
        // TODO
    }

    fn Response::to_wire(&self, w) {
        // TODO
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[/* TODO */],
            value: {command}Request { /* TODO */ },
        },
        response_round_trip: {
            bytes: &[/* TODO */],
            value: {command}Response { /* TODO */ },
        },
    }
}
