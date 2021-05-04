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
    let pid = std::process::id();
    env_logger::builder()
        .format(move |buf, record| {
            use std::io::Write;
            for line in record.args().to_string().trim().lines() {
                writeln!(
                    buf,
                    "[{level}{pid} {file}:{line}] {msg}",
                    level = record.level().to_string().chars().next().unwrap(),
                    pid = pid,
                    file = record.file().unwrap_or("?.rs"),
                    line = record.line().unwrap_or(0),
                    msg = line,
                )?;
            }
            Ok(())
        })
        .init();
    for (i, arg) in std::env::args_os().enumerate() {
        log::info!("argv[{}] = {:?}", i, arg);
    }

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

            subproc.kill().unwrap();
        }
        Options::Serve(opts) => pa_rot::serve(opts),
    }
}
