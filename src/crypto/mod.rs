// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable cryptograpy traits.
//!
//! `manticore` requires cryptographic primitives to function.
//! This module provides traits that abstract over those operations, in the
//! following general pattern for each algorithm:
//! ```
//! trait Builder {
//!   type Engine: Engine;
//!   fn with_key(&self, key: &[u8]) -> Self::Engine;
//! }
//!
//! trait Engine {
//!   fn do_it(&mut self, buf: &[u8]);
//! }
//! ```
//! The "builder" trait represents a way to construct a "primed" instance of a
//! primitive, for performing a specific operation, while the "engine"
//! allows the caller to feed in a message to be operated on.
//!
//! Types that need to perform many operations of a particular type should
//! carry around a `Builder`, while shorter-lived types, that only need to
//! be using a single key (which they might not have access to directly!)
//! should carry arround a pre-primed `Engine`, instead.
//!
//! It is recommended to not import the traits in this module directly, since
//! a lot of them have the same name. Instead, use imports like
//! `use manticore::crypto::sha256;` and partially-qualified names like
//! `sha256::Hasher`.
//!
//! Software implementations of thes traits are provided under the
//! [`ring` module], based on the [`ring`] crate. Their presence is controlled
//! by the `ring` feature flag; some opeartions require `std` as well.
//!
//! [`ring` module]: ring/index.html

pub mod rsa;
pub mod sha256;
pub mod sig;

#[cfg(feature = "ring")]
pub mod ring;
