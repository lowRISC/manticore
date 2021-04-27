// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! The ability for an RoT to respond to requests.

use crate::mem::Arena;
use crate::net;
use crate::server::Error;

/// The ability for an RoT to respond to requests.
pub trait Respond {
    /// Process a single incoming request.
    ///
    /// The request message will be read from `req`, while the response
    /// message will be written to `resp`.
    fn process_request<'req>(
        &mut self,
        host_port: &mut dyn net::HostPort,
        arena: &'req impl Arena,
    ) -> Result<(), Error>;
}
