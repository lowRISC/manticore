// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `manticore` is a partial implementation of the [Cerberus] attestation
//! protocol for Root of Trust devices.
//!
//! Throughout the documentation of this crate, we use "Cerberus" to refer to
//! the specification as published. `manticore` is not a complete
//! implementation, and we take care to point out where it varies from
//! Cerberus.
//!
//! For example, protocol ["commands"](protocol/trait.Command.html) are a
//! Cerberus concept, although `manticore` adds its own (very clearly labeled)
//! commands. The [FPM](manifest/fpm/index.html) is a `manticore`-specific
//! concept, on the other hand, although it is derived from the Cerberus PFM.
//!
//! `manticore` also does not use MCTP, unlike Cerberus. Instead, `manticore`
//! abstracts away the packet layer in terms of sized buffers, so that it can
//! be used with any packet layer, such as MCTP, TCP, or ring-buffer IPC. See
//! the [`protocol` module] for more details.
//!
//! # Feature flags
//!
//! `manticore` provides a number of optional features that can be controlled
//! through feature flags:
//! - `std` (default) pulls in the full Rust standard library. This is
//!   not necessary for any on-device use-cases, but is available for using
//!   `manticore` as a library for talking to Cerberus devices.
//! - `ring` (default) enables the [`crypto::ring` module], which provides
//!   software implementations for cryptography traits used by `manticore`.
//!   This feature is not intended for on-device use-cases either.
//! - `serde` enables implementations of `serde`'s (de)serialization traits.
//! - `arbitrary-derive` enables implementations of fuzz-testing-related
//!   traits.
//!
//! [Cerberus]:
//!   https://github.com/opencomputeproject/Project_Olympus/tree/master/Project_Cerberus
//! [`protocol` module]: protocol/index.html
//! [`crypto::ring` module]: crypto/ring/index.html

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![deny(warnings)]
#![deny(unused)]
#![deny(unsafe_code)]

#[macro_use]
pub mod protocol;

pub mod crypto;
pub mod hardware;
pub mod io;
pub mod manifest;
pub mod mem;
pub mod net;
pub mod server;
