// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for Manticore.
//!
//! This crate operates as follows. When run as `./e2e run-tests`, it will
//! re-exec a copy of the process via `./e2e serve`. This new process is a
//! "virtual RoT", which is connected back to the parent over a TCP "bus".
//! The parent can then actuate the virtual RoT as a sort of black box.
//!
//! This crate serves two major purposes:
//! 1. To provide an easy way to black-box test Manticore; in the future, we'd
//!    like to be able to make it possible to test other implementations, such
//!    as Azure's Cerberus implementation.
//! 2. To provide an example *integration* for platform integrators to
//!    understand how to build a Cerberus-compliant device using Manticore's
//!    toolkit.

#![deny(warnings)]
#![deny(unused)]
#![deny(unsafe_code)]
#![deny(missing_docs)]

use structopt::StructOpt;

use manticore::mem::BumpArena;
use manticore::protocol::firmware_version::FirmwareVersion;
use manticore::protocol::firmware_version::FirmwareVersionRequest;

pub mod pa_rot;
pub mod tcp;

/// End-to-end tests for Manticore.
#[derive(Debug, StructOpt)]
struct Options {
    /// Internal flag.
    #[structopt(long)]
    start_pa_rot_with_options: Option<String>,
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

    let opts = Options::from_args();
    if let Some(pa_opts) = &opts.start_pa_rot_with_options {
        let opts = serde_json::from_str::<pa_rot::Options>(pa_opts).unwrap();
        pa_rot::serve(opts);
    }

    // Currently, we only run one, trivial test.
    // Eventually, this will be replaced with a more general "test
    // suite".
    let virt = pa_rot::Virtual::spawn(&pa_rot::Options {
        firmware_version: b"my cool e2e test".to_vec(),
        ..Default::default()
    });

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
