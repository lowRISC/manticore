// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// !! DO NOT EDIT !!
// To regenerate this file, run `fuzz/generate_proto_tests.py`.

#![no_main]
#![allow(non_snake_case)]

use libfuzzer_sys::fuzz_target;

use manticore::protocol::Command;
use manticore::protocol::wire::ToWire;
use manticore::protocol::borrowed::AsStatic;
use manticore::protocol::borrowed::Borrowed;

use manticore::protocol::device_id::DeviceId as C;
type Req<'a> = <C as Command<'a>>::Req;

fuzz_target!(|data: AsStatic<'static, Req<'static>>| {
    let mut out = [0u8; 1024];
    let _ = Req::borrow(&data).to_wire(&mut &mut out[..]);
});

