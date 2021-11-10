// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Tests for device-interrogation messages.

use manticore::mem::BumpArena;
use manticore::protocol::spdm;
use manticore::protocol::Req;

use crate::support::rot;
use crate::support::rot::Protocol::Spdm;

#[test]
fn query_device() {
    let virt = rot::Virtual::spawn(&rot::Options {
        protocol: Spdm,
        ..Default::default()
    });

    let arena = BumpArena::new([0; 64]);

    let resp =
        virt.send_spdm::<spdm::GetVersion>(Req::<spdm::GetVersion> {}, &arena);

    let versions = resp.unwrap().unwrap().versions;
    assert_eq!(versions, &[spdm::ExtendedVersion::MANTICORE]);
}
