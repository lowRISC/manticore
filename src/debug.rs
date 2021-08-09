// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Debug-logging functionality.
//!
//! This module is still present when the `log` feature is disabled, but all
//! logging operations are redacted. Redaction completely compiles out log
//! statements: not even the format strings remain in the final binary.
//!
//! Manticore code *should not* call into the [`log`] crate directly outside of
//! this module.

#![allow(unused)]

#[cfg(doc)]
use __raw_log as log;

/// Checks a condition, logging if it fails.
///
/// If the condition does not hold, constructs the given error, logs it, and
/// returns out of the current function with it.
macro_rules! check {
    ($cond:expr, $error:expr) => {
        if !$cond {
            let e = $error;
            error!(
                "check failure: `{}`; returned {:?}"
                stringify!($cond), e
            );
            return Err(e);
        }
    }
}

/// Logs a newly-created error value and returns it.
///
/// This function is useful for marking where errors originate in tests.
/// For example, instead of writing `foo.ok_or(MyError)`, instead write
/// `foo.ok_or_else(|| trace!(MyError))`.
macro_rules! trace {
    ($error:expr, $($format:tt)+) => {{
        error!($($format)+);
        $error
    }};
    ($error:expr) => {{
        let e = $error;
        error!("generated error: `{:?}`", e);
        e
    }};
}

/// Redactable version of [`log::info!()`].
macro_rules! info {
    ($($args:tt)*) => {
        #[cfg(feature = "log")]
        let _ = __raw_log::info!($($args)*);
    }
}

/// Redactable version of [`log::warn!()`].
macro_rules! warn {
    ($($args:tt)*) => {
        #[cfg(feature = "log")]
        let _ = __raw_log::warn!($($args)*);
    }
}

/// Redactable version of [`log::error!()`].
macro_rules! error {
    ($($args:tt)*) => {
        #[cfg(feature = "log")]
        let _ = __raw_log::error!($($args)*);
    }
}

/// Set up some life-before-main code that initializes a basic logger for the
/// test binary.
///
/// This needs to happen here, since the test binary's main() cannot be
/// overriden.
#[cfg(test)]
#[ctor::ctor]
fn init_test_logger() {
    env_logger::builder()
        .format(move |_, record| {
            use std::io::Write;

            let thread = std::thread::current();
            let name = thread.name().unwrap_or("<unknown>");
            for line in record.args().to_string().trim().lines() {
                // NOTE: we explicitly print to stderr, since this allows the
                // Rust test harness to supress log statements originating from
                // passing tests.
                eprintln!(
                    "[{level}({thread}) {file}:{line}] {msg}",
                    level = record.level(),
                    thread = name,
                    file = record.file().unwrap_or("<unknown>"),
                    line = record.line().unwrap_or(0),
                    msg = line,
                )
            }
            Ok(())
        })
        .init();
}
