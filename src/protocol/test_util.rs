// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Test-only utilities for (de)serializing `manticore` messages.

use crate::protocol::wire::FromWire;
use crate::protocol::wire::ToWire;
use crate::protocol::Header;
use crate::protocol::Request;
use crate::protocol::Response;

/// ToWire a header + request onto a buffer.
///
/// Returns the portion of `out` written to.
///
/// # Panics
///
/// This function will panic on all errors, to help with testing.
pub fn write_req<'a, 'req, Req: Request<'req>>(
    req: Req,
    buf: &'a mut [u8],
) -> &'a mut [u8] {
    with_buf(buf, move |buf| {
        Header {
            is_request: true,
            command: Req::TYPE,
        }
        .to_wire(buf)
        .expect("failed to write header");
        req.to_wire(buf).expect("failed to write request");
    })
}

/// FromWire a header + response from a buffer.
///
/// Returns the parsed response.
///
/// # Panics
///
/// This function will panic on all errors, to help with testing. This includes
/// panicking when the the parsed header has unexpected values.
pub fn read_resp<'req, Resp: Response<'req>>(mut buf: &'req [u8]) -> Resp {
    let expected_header = Header {
        is_request: false,
        command: Resp::TYPE,
    };
    let buf = &mut buf;

    let header = Header::from_wire(buf).expect("failed to parse header");
    assert_eq!(header, expected_header);
    Resp::from_wire(buf).expect("failed to parse response")
}

/// Perform the operation `f` on `buf`, returning whatever portion of `buf`
/// was consumed.
pub fn with_buf(buf: &mut [u8], f: impl FnOnce(&mut &mut [u8])) -> &mut [u8] {
    let buf_ref = &mut &mut *buf;
    let start_len = buf_ref.len();
    f(buf_ref);
    let end_len = buf_ref.len();
    &mut buf[..start_len - end_len]
}
