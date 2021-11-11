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

mod error;
pub use error::*;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};

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

/// An protocol SPDM version, consisting of a pair of nybble-sized major and
/// minor versions.
///
/// The high bit is the major version; the low bit is the minor version.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    zerocopy::FromBytes,
    zerocopy::AsBytes,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[repr(transparent)]
pub struct Version {
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
    version: u8,
}
derive_borrowed!(Version);

impl Version {
    /// The version of SPDM that Manticore implements.
    pub const MANTICORE: Self = Self::new(1, 2);

    /// Returns a new `Version` with the given parts.
    ///
    /// Note: `major` and `minor` should be `u4`s; the high bits are discarded.
    pub const fn new(major: u8, minor: u8) -> Self {
        Self {
            version: major << 4 | (minor & 0xf),
        }
    }

    /// Returns the major version.
    pub const fn major(self) -> u8 {
        self.version >> 4
    }

    /// Returns the minor version.
    pub const fn minor(self) -> u8 {
        self.version & 0xf
    }

    /// Returns this version's encoded byte.
    pub const fn byte(self) -> u8 {
        self.version
    }
}

impl From<u8> for Version {
    fn from(version: u8) -> Self {
        Self { version }
    }
}

/// An extended SPDM protocol version, consiting of a [`Version`] plus revision
/// and alpha nybbles.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    zerocopy::FromBytes,
    zerocopy::AsBytes,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[repr(C)]
pub struct ExtendedVersion {
    // Note: this field ordering is significant for zero-copy
    // reads.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "crate::serde::is_default")
    )]
    extension: u8,
    version: Version,
}
derive_borrowed!(ExtendedVersion);

impl ExtendedVersion {
    /// The extended version of SPDM Manticore implements.
    pub const MANTICORE: Self = Self::new(Version::MANTICORE, 0, 0);

    /// Returns a new `Version` with the given parts.
    ///
    /// Note: `revision` and `alpha` should be `u4`s; the high bits are discarded.
    pub const fn new(version: Version, revision: u8, alpha: u8) -> Self {
        Self {
            version,
            extension: revision << 4 | (alpha & 0xf),
        }
    }

    /// Returns the main version.
    pub const fn version(self) -> Version {
        self.version
    }

    /// Returns the version revision.
    pub const fn revision(self) -> u8 {
        self.extension >> 4
    }

    /// Returns the alpha value.
    pub const fn alpha(self) -> u8 {
        self.extension & 0xf
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

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::AsBytes as _;

    #[test]
    fn version_byte_values() {
        let v1 = Version::MANTICORE;
        let v2 = Version::new(0x1f, 0x1e);
        let v3 = ExtendedVersion::new(v1, 5, 6);
        assert_eq!(v1.as_bytes(), [0x12]);
        assert_eq!(v2.as_bytes(), [0xfe]);
        assert_eq!(v3.as_bytes(), [0x56, 0x12]);
    }

    #[test]
    fn version_getters() {
        let v1 = Version::MANTICORE;
        let v2 = Version::new(0x1f, 0x1e);
        let v3 = ExtendedVersion::new(v1, 5, 6);
        assert_eq!(v1.major(), 1);
        assert_eq!(v1.minor(), 2);
        assert_eq!(v2.major(), 15);
        assert_eq!(v2.minor(), 14);
        assert_eq!(v3.version(), v1);
        assert_eq!(v3.revision(), 5);
        assert_eq!(v3.alpha(), 6);
    }
}
