// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// !! DO NOT EDIT !!
// To regenerate this file, run `fuzz/generate_proto_tests.py`.

#![no_main]
#![allow(non_snake_case)]

use libfuzzer_sys::fuzz_target;

use manticore::mem::BumpArena;
use manticore::protocol::Command;
use manticore::protocol::wire::FromWire;

use manticore::protocol::cerberus::DeviceId as C;

fuzz_target!(|data: &[u8]| {
    let mut arena = vec![0; data.len()];
    let arena = BumpArena::new(&mut arena);
    let mut data = data;
    let _ = <C as Command<'_>>::Resp::from_wire(&mut data, &arena);
});

