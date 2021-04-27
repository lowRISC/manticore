// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `manticore` "server" implementations
//!
//! A `manticore` "server" is software running on an RoT which responds to
//! incoming requests from the host or another RoT.
//!
//! TODO: description of how to use a server.

mod handler;
pub use handler::Error;

pub mod options;
pub mod pa_rot;
