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
use manticore::protocol::FuzzSafe;

use manticore::protocol::device_uptime::DeviceUptime as C;
type Resp<'a> = <C as Command<'a>>::Req;

fuzz_target!(|data: <Resp<'static> as FuzzSafe>::Safe| {
    let mut out = [0u8; 1024];
    let _ = Resp::from_safe(&data).to_wire(&mut &mut out[..]);
});

