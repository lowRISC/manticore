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

use manticore::protocol::firmware_version::FirmwareVersion as C;

fuzz_target!(|data: <<C as Command<'static>>::Resp as FuzzSafe>::Safe| {
    let mut out = [0u8; 1024];
    let _ = data.to_wire(&mut &mut out[..]);
});

