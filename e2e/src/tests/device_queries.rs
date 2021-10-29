// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Tests for device-interrogation messages.

use manticore::mem::BumpArena;

use crate::pa_rot;

#[test]
fn firmware_version() {
    use manticore::protocol::firmware_version::*;

    let virt = pa_rot::Virtual::spawn(&pa_rot::Options {
        firmware_version: b"my cool e2e test".to_vec(),
        ..Default::default()
    });

    let arena = BumpArena::new([0; 64]);
    let resp = virt.send_local::<FirmwareVersion, _>(
        FirmwareVersionRequest { index: 0 },
        &arena,
    );

    let version = resp.unwrap().unwrap().version;
    assert!(version.starts_with(b"my cool e2e test"));
}

#[test]
fn vendor_firmware_version() {
    use manticore::protocol::firmware_version::*;

    let virt = pa_rot::Virtual::spawn(&pa_rot::Options {
        vendor_firmware_versions: vec![
            (1, b"my version".to_vec()),
            (3, b"my other version".to_vec()),
        ],
        ..Default::default()
    });

    let arena = BumpArena::new([0; 64]);
    let resp = virt.send_local::<FirmwareVersion, _>(
        FirmwareVersionRequest { index: 1 },
        &arena,
    );

    let version = resp.unwrap().unwrap().version;
    assert!(version.starts_with(b"my version"));
}

#[test]
fn vendor_firmware_version_out_of_range() {
    use manticore::protocol::firmware_version::*;

    let virt = pa_rot::Virtual::spawn(&pa_rot::Options {
        vendor_firmware_versions: vec![
            (1, b"my version".to_vec()),
            (3, b"my other version".to_vec()),
        ],
        ..Default::default()
    });

    let arena = BumpArena::new([0; 64]);
    let resp = virt.send_local::<FirmwareVersion, _>(
        FirmwareVersionRequest { index: 2 },
        &arena,
    );

    resp.unwrap().expect_err("expected error from server");
}

#[test]
fn device_id() {
    use manticore::protocol::device_id::*;

    let virt = pa_rot::Virtual::spawn(&pa_rot::Options {
        device_id: DeviceIdentifier {
            vendor_id: 0xc020,
            device_id: 0x0001,
            subsys_vendor_id: 0xffff,
            subsys_id: 0xaa55,
        },
        ..Default::default()
    });

    let arena = BumpArena::new([0; 64]);
    let resp = virt.send_local::<DeviceId, _>(DeviceIdRequest {}, &arena);
    assert_eq!(
        resp.unwrap().unwrap().id,
        DeviceIdentifier {
            vendor_id: 0xc020,
            device_id: 0x0001,
            subsys_vendor_id: 0xffff,
            subsys_id: 0xaa55,
        }
    );
}
