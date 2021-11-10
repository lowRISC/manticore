// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for Manticore.
//!
//! This crate serves two major purposes:
//! 1. To provide an easy way to black-box test Manticore; in the future, we'd
//!    like to be able to make it possible to test other implementations, such
//!    as Azure's Cerberus implementation.
//! 2. To provide an example *integration* for platform integrators to
//!    understand how to build a Cerberus-compliant device using Manticore's
//!    toolkit.
//!
//! See the outer README.md for more information.

#![deny(warnings)]
#![deny(unused)]
#![deny(unsafe_code)]
#![deny(missing_docs)]

use structopt::StructOpt;

pub mod support;

#[cfg(test)]
mod tests {
    mod challenge;
    mod device_queries;
    mod spdm_device_queries;
}

/// End-to-end tests for Manticore.
#[derive(Debug, StructOpt)]
struct Options {
    /// Internal flag.
    #[structopt(long)]
    start_pa_rot_with_options: Option<String>,
}

#[cfg_attr(test, ctor::ctor)]
fn logging_setup() {
    let pid = std::process::id();
    env_logger::builder()
        .format(move |#[allow(unused)] buf, record| {
            // Log to stderr in tests, in order to trigger output capture.
            #[cfg(test)]
            macro_rules! logln {
               ($($tt:tt)*) => {eprintln!($($tt)*)};
            }
            #[cfg(not(test))]
            macro_rules! logln {
                ($($tt:tt)*) => {{
                    use std::io::Write;
                    writeln!(buf, $($tt)*)?
                }};
            }

            for line in record.args().to_string().trim().lines() {
                logln!(
                    "[{level}{pid} {file}:{line}] {msg}",
                    level = record.level().to_string().chars().next().unwrap(),
                    pid = pid,
                    file = record.file().unwrap_or("?.rs"),
                    line = record.line().unwrap_or(0),
                    msg = line,
                )
            }
            Ok(())
        })
        .init();
}

fn main() {
    logging_setup();
    for (i, arg) in std::env::args_os().enumerate() {
        log::info!("argv[{}] = {:?}", i, arg);
    }

    let opts = Options::from_args();
    if let Some(pa_opts) = &opts.start_pa_rot_with_options {
        use support::rot::*;
        let opts = serde_json::from_str::<Options>(pa_opts).unwrap();
        serve(opts);
    }
}
