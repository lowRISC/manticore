// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Device info interrogation tests.

pa_tests! {
    use crate::pa_rot;

    use manticore::mem::BumpArena;
    use manticore::protocol::device_id::DeviceIdentifier;

    #[pa_test(opts = {
        firmware_version: b"my cool e2e test".to_vec(),
    })]
    fn firmware_version(virt: &pa_rot::Virtual) {
        use manticore::protocol::firmware_version::*;

        let mut arena = [0; 64];
        let arena = BumpArena::new(&mut arena);
        let resp = virt.send_local::<FirmwareVersion, _>(
            FirmwareVersionRequest { index: 0 },
            &arena,
        );
        match resp {
            Ok(Ok(resp)) => {
                log::info!(
                    "resp.version: {}",
                    std::str::from_utf8(resp.version).unwrap()
                );
                assert!(resp.version.starts_with(b"my cool e2e test"));
            }
            bad => log::error!("bad response: {:?}", bad),
        }
    }

    const DEV_ID: DeviceIdentifier = DeviceIdentifier {
        vendor_id: 0xff,
        device_id: 200,
        subsys_vendor_id: 3,
        subsys_id: 4,
    };

    #[pa_test(opts = {device_id: DEV_ID})]
    fn device_id(virt: &pa_rot::Virtual) {
        use manticore::protocol::device_id::*;

        let mut arena = [0; 64];
        let arena = BumpArena::new(&mut arena);
        let resp = virt.send_local::<DeviceId, _>(
            DeviceIdRequest,
            &arena,
        );
        match resp {
            Ok(Ok(resp)) => {
                log::info!("resp.id: {:?}", resp.id);
                assert_eq!(resp.id, DEV_ID);
            }
            bad => log::error!("bad response: {:?}", bad),
        }
    }
}
