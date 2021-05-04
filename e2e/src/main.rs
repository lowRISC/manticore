// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]
#![deny(unused)]
#![deny(unsafe_code)]
//#![deny(missing_docs)]

use structopt::StructOpt;

use manticore::mem::BumpArena;
use manticore::protocol::firmware_version::FirmwareVersion;
use manticore::protocol::firmware_version::FirmwareVersionRequest;

pub mod pa_rot;
pub mod tcp;

#[derive(Debug, StructOpt)]
enum Options {
    RunTests {
        #[structopt(long, short, default_value = "9999")]
        port: u16,
    },
    Serve(pa_rot::Options),
}

fn main() {
    let _ = Options::from_args();
    match Options::from_args() {
        Options::RunTests { port, .. } => {
            let mut subproc = pa_rot::Options {
                port,
                firmware_version: b"my cool e2e test".to_vec(),
                ..Default::default()
            }
            .self_exec();

            let mut arena = [0; 64];
            let arena = BumpArena::new(&mut arena);
            let resp = tcp::send_local::<FirmwareVersion, _>(
                port,
                FirmwareVersionRequest { index: 0 },
                &arena,
            )
            .unwrap()
            .unwrap();

            eprintln!(
                "resp.version: {}",
                std::str::from_utf8(resp.version).unwrap()
            );
            assert!(resp.version.starts_with(b"my cool e2e test"));

            subproc.kill().unwrap();
        }
        Options::Serve(opts) => pa_rot::serve(opts),
    }
}
