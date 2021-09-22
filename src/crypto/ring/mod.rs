// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of crypto traits, using the [`ring`] crate.
//!
//! This module provides software implemenations of [`crypto`] traits suitable
//! for use in non-integration uses of `manticore`, such as in tools that talk
//! to a `manticore` integration. In particular, some submodules have
//! dependencies on the `std` feature flag.
//!
//! Types in this module, much like those in [`crypto`], should not be imported
//! directly. Instead, names such as `ring::rsa::Keypair` should be used
//! instead.
//!
//! The [`ring` warranty disclaimer] applies to this module as well.
//!
//! [`ring` warranty disclaimer]: https://github.com/briansmith/ring/blob/main/README.md

#[cfg(feature = "std")]
pub mod csrng;
#[cfg(feature = "std")]
pub mod ecdsa;
pub mod hash;
#[cfg(feature = "std")]
pub mod rsa;
#[cfg(feature = "std")]
pub mod sig;

#[cfg(doc)]
use crate::crypto;

pub use ring::error::Unspecified;
