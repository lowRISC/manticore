// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable cryptograpy traits.
//!
//! Manticore requires cryptographic primitives to function.
//! This module provides object-safe traits that abstract over those
//! operations.
//!
//! Users are expected to provide their own implementations of these traits,
//! which may suit particular hardware or certification needs that Manticore
//! cannot fulfill.
//!
//! It is recommended to not import the traits in this module directly, since
//! a lot of them have the same name. Instead, use imports like
//! `use manticore::crypto::hash;` and partially-qualified names like
//! `hash::Engine`.
//!
//! Software implementations of thes traits are provided under the
//! [`ring` module], based on the [`ring`] crate. Their presence is controlled
//! by the `ring` feature flag; some opeartions require `std` as well.
//!
//! [`ring` module]: ring/index.html

pub mod csrng;
pub mod hash;
pub mod sha256;
pub mod sig;

#[cfg(feature = "ring")]
pub mod ring;
