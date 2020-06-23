// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// NOTE: This file is autogenerated by:
// $ util/new_protocol_target.py reset_counter::ResetCounterResponse

#![no_main]

use libfuzzer_sys::fuzz_target;

use manticore::protocol::Serialize;
use manticore::protocol::reset_counter::ResetCounterResponse;

fuzz_target!(|data: ResetCounterResponse| {
    let mut out = [0u8; 1024];
    let _ = data.serialize(&mut &mut out[..]);
});

