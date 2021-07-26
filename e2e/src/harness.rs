// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Test harness and related macros.

use std::cell::Cell;
use std::panic;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Instant;

use crate::pa_rot;

/// A single test for the PaRot.
pub struct PaTest {
    /// The full module path for the test.
    pub full_path: &'static str,
    /// A generator for this test's options.
    pub opts: fn() -> pa_rot::Options,
    /// The actual code under tests.
    pub test: fn(&pa_rot::Virtual),
}

/// The global set of PaRot tests.
#[linkme::distributed_slice]
pub static PA_TESTS: [PaTest] = [..];

/// Executes all PaRot end-to-end tests, producing an appropriate exit
/// code.
pub fn run_pa_tests() -> ! {
    let failures = Arc::new(Mutex::new(Vec::new()));
    thread_local! {
        static CURRENT: Cell<Option<&'static PaTest>> = Cell::new(None);
    }

    let hook = panic::take_hook();
    let hook_failures = Arc::clone(&failures);
    panic::set_hook(Box::new(move |panic| {
        let t = match CURRENT.with(Cell::get) {
            Some(t) => t,
            None => return hook(panic),
        };
        hook_failures.lock().unwrap().push((t, panic.to_string()));
    }));

    let start = Instant::now();
    let mut joins = Vec::new();
    for test in PA_TESTS {
        joins.push((
            test,
            thread::spawn(move || {
                CURRENT.with(|t| t.set(Some(test)));
                let opts = (test.opts)();
                let virt = pa_rot::Virtual::spawn(&opts);
                (test.test)(&virt);
            }),
        ));
    }

    eprintln!("running {} tests", joins.len());
    for (test, join) in joins {
        eprint!("test {}... ", test.full_path);
        match join.join() {
            Ok(()) => eprintln!("ok"),
            Err(_) => eprintln!("failed"),
        }
    }
    let total_time = start.elapsed();

    eprintln!();

    let failures = &*failures.lock().unwrap();
    for (test, failure) in failures {
        eprintln!("test failed: {}\n{}\n", test.full_path, failure);
    }

    eprintln!(
        "{}/{} tests passed in {:.2}s",
        PA_TESTS.len() - failures.len(),
        PA_TESTS.len(),
        total_time.as_secs_f32()
    );

    std::process::exit(!failures.is_empty() as i32)
}

/// Macro for generating PaRot tests.
///
/// Syntax:
/// ```text
/// pa_tests! {
///    #[pa_test(opts = {
///         // Options to pass to the subprocess via
///         // pa_rot::Options,
///    })]
///    fn firmware_version(virt: &pa_rot::Virtual) {
///        // Test code...
///    }
/// }
/// ```
macro_rules! pa_tests {
    (
        #[pa_test(opts = {$($f:ident:$opt:expr),* $(,)?})]
        fn $name:ident($arg:ident:$argty:ty) {
            $($body:tt)*
        }
        $($rest:tt)*
    ) => {
        #[allow(unused)]
        fn $name() {
            use $crate::harness::*;
            #[linkme::distributed_slice(PA_TESTS)]
            static TEST: PaTest = PaTest {
                full_path: concat!(module_path!(), "::", stringify!($name)),
                opts: || pa_rot::Options {
                    $($f:$opt,)*
                    ..Default::default()
                },
                test: |$arg:$argty| { $($body)* },
            };
        }
        pa_tests!($($rest)*);
    };
    ($item:item $($rest:tt)*) => {
        $item
        pa_tests!($($rest)*);
    };
    () => {};
}
