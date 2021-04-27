// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Options for a `manticore` "server" and "client" for a RoT.

use crate::protocol::capabilities;
use crate::protocol::device_id;
#[cfg(doc)]
use crate::server::pa_rot::PaRot;

/// Options struct for initialising a [`PaRot`].
pub struct Options<'a, Identity, Reset, Rsa> {
    /// A handle to the "hardware identity" of the device.
    pub identity: &'a Identity,
    /// A handle for looking up reset-related information for the current
    /// device.
    pub reset: &'a Reset,

    /// A handle to an RSA engine builder.
    pub rsa: &'a Rsa,

    /// This device's silicon identifier.
    pub device_id: device_id::DeviceIdentifier,
    /// Integration-provided description of the device's networking
    /// capabilities.
    pub networking: capabilities::Networking,
    /// Integration-provided "acceptable timeout" lengths.
    pub timeouts: capabilities::Timeouts,
}
