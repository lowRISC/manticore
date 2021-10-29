// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! SPDM  protocol messages.

use crate::io::Read;
use crate::io::ReadInt as _;
use crate::io::Write;
use crate::protocol::wire;

pub mod get_version;
pub use get_version::GetVersion;

pub mod get_caps;
pub use get_caps::GetCaps;

wire_enum! {
    /// An SPDM command type.
    ///
    /// This enum represents all command types implemented by Manticore.
    ///
    /// Note that the code values represent the "response" code; to get the
    /// corresponding request code, the top bit should be set.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[allow(missing_docs)]
    pub enum CommandType: u8 {
        GetDigests = 0x01,
        GetCert = 0x02,
        Challenge = 0x03,
        GetVersion = 0x04,
        GetMeasurements = 0x60,
        GetCaps = 0x61,
        GetAlgos = 0x62,
        KeyExchange = 0x63,
        Finish = 0x64,
        Heartbeat = 0x68,
        EndSession = 0x6c,
        GetCsr = 0x6d,
        SetCert = 0x6e,
        VendorDefined = 0x7e,
        Error = 0x7f,
    }
}

/// Utility function for reading `count` zeroes in a row.
fn expect_zeros(
    r: &mut (impl Read + ?Sized),
    count: usize,
) -> Result<(), wire::Error> {
    for _ in 0..count {
        if r.read_le::<u8>()? != 0 {
            return Err(wire::Error::OutOfRange);
        }
    }
    Ok(())
}

fn write_zeros(w: &mut impl Write, count: usize) -> Result<(), wire::Error> {
    for _ in 0..count {
        w.write_le(0u8)?;
    }
    Ok(())
}
