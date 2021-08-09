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

// TODO: Remove this once we start using these macros in Manticore.
#![allow(unused)]

use core::fmt;

#[cfg(doc)]
use __raw_log as log;

/// A wrapped Manticore error.
///
/// This type should always be referred to as `manticore::Error`. It represents
/// an error with extra (potentially redacted) information attached. This type
/// cannot be directly created by users of the library.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Error<E> {
    inner: E,
}

impl<E> Error<E> {
    /// Creates a new `Error`. This function is an implementation detail,
    /// and should not be called by users.
    #[doc(hidden)]
    pub fn __new(inner: E) -> Self {
        Self { inner }
    }

    /// Transforms the wrapper error by way of an [`Into`] conversion.
    ///
    /// Generally, this function should not be necessary, because Manticore-
    /// defined error types manually implement the relevant [`From`]
    /// implementations for `manticore::Error`, which in turn call `cast()`.
    pub fn cast<F: From<E>>(self) -> Error<F> {
        Error {
            inner: self.inner.into(),
        }
    }

    /// Gets the wrapped error.
    pub fn into_inner(self) -> E {
        self.inner
    }
}

impl<E> AsRef<E> for Error<E> {
    fn as_ref(&self) -> &E {
        &self.inner
    }
}

impl<E> AsMut<E> for Error<E> {
    fn as_mut(&mut self) -> &mut E {
        &mut self.inner
    }
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct DisplayAsDebug<'a, E>(&'a E);
        impl<E: fmt::Display> fmt::Debug for DisplayAsDebug<'_, E> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        f.debug_struct("manticore::Error")
            .field("inner", &DisplayAsDebug(&self.inner))
            .finish()
    }
}

/// Generates `From` implementations for `manticore::Error`.
///
/// We would like to write this `impl`:
/// ```compile_fail
/// # use manticore::Error;
/// impl<E1, E2> From<Error<E1>> for Error<E2> where E2: From<E1> {
///     fn from(e: Error<E1>) -> Error<E2> {
///         e.cast()
///     }
/// }
/// ```
///
/// Unfortunately, the trait coherence rules mean that for `E1 == E2`,
/// this conflicts with the standard library's `impl<T> From<T> for T`
/// impl. We work around this by calling this macro for every Manticore
/// error definition that has `From` impls.
macro_rules! debug_from {
    // An error generic over one type with a single trait bound
    ($e:ident<$trait:ident: $bound:path> => $($f:ty),+ $(,)?) => {$(
        impl<$trait: $bound> From<$crate::Error<$f>> for $crate::Error<$e<$trait>> {
            fn from(e: $crate::Error<$f>) -> Self {
                e.cast()
            }
        }
    )*};
    // An error generic over one type
    ($e:ident<$trait:ident> => $($f:ty),+ $(,)?) => {$(
        impl<$trait> From<$crate::Error<$f>> for $crate::Error<$e<$trait>> {
            fn from(e: $crate::Error<$f>) -> Self {
                e.cast()
            }
        }
    )*};
    ($e:ty => $($f:ty),+ $(,)?) => {$(
        impl From<$crate::Error<$f>> for $crate::Error<$e> {
            fn from(e: $crate::Error<$f>) -> Self {
                e.cast()
            }
        }
    )*};
}

/// Checks a condition, logging if it fails.
///
/// If the condition does not hold, constructs the given error, logs it, and
/// returns out of the current function with it.
macro_rules! check {
    ($cond:expr, $error:expr) => {
        if !$cond {
            let error = $error;
            fail!(
                error,
                "check failure: `{}`; returned {:?}",
                stringify!($cond),
                error,
            )?;
        }
    };
}

/// Logs a newly-created error value and returns it.
///
/// This macro is the main way to generate [`Error`] values.
///
/// For example, instead of writing `foo.ok_or(MyError)`, instead write
/// `foo.ok_or_else(|| fail!(MyError))`.
macro_rules! fail {
    ($error:expr, $($format:tt)+) => {{
        error!($($format)+);
        Err($crate::debug::Error::__new($error))
    }};
    ($error:expr) => {{
        let error = $error;
        error!("generated error: `{:?}`", error);
        Err($crate::debug::Error::__new(error))
    }};
}

/// Redactable version of [`log::trace!()`].
macro_rules! trace {
    ($($args:tt)*) => {
        #[cfg(feature = "log")]
        let _ = __raw_log::trace!($($args)*);
    }
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
/// overridden.
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
                // Rust test harness to suppress log statements originating from
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
