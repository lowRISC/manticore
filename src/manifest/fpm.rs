// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! The Firmware Policy Manifest (FPM)
//!
//! An FPM is a computer-readable policy document describing firmware which is
//! allowed to run on a device. Practically, this means that an FPM describes
//! an allowed configuration of an external storage device, such as a SPI
//! flash device.
//!
//! The FPM is a list of "allowed firmware versions", each containing:
//! - A unique version string.
//! - A partition of a flash device into signed regions (containing code that
//!   the platform can't change at runtime), writeable regions (which are used
//!   as nonvolatile storage by the host), and unused regions.
//! - A hash of the contents of the signed regions.
//! - A "blank byte", which every unused region must be filled with.
//!
//! Although the FPM body does not contain a signature, the overall
//! [`Manifest`] container does. That signature is extended to encompass the
//! signed regions through the signed region hash.
//!
//! An FPM can be used to verify that a storage device conforms to the the
//! partitioning requirements described above.
//!
//! On the wire, the FPM is encoded as follows:
//! ```text
//! struct Fpm {
//!     /// Number of firmware versions included.
//!     fw_count: u32,
//!     /// The versions themselves.
//!     versions: [FwVersion; self.fw_count],
//! }
//!
//! struct FwVersion {
//!     /// An address in flash where the firmware version is expected to
//!     /// be present.
//!     version_addr: u32,
//!     /// The number of signed region parts.
//!     signed_region_count: u16,
//!     /// The number of write region parts.
//!     write_region_count: u16,
//!     /// The "blank byte" used to fill unused regions.
//!     blank_byte: u8,
//!     /// The length of the version string.
//!     version_len: u8,
//!     /// The version string itself.
//!     version: [u8; self.version_len],
//!     /// Alignment padding, up to 4 bytes.
//!     _: [u8; ???],
//!     /// Region parts, given as pointer-length pairs.
//!     signed_region: [(u32, u32); self.signed_region_count],
//!     write_region: [(u32, u32); self.write_region_count],
//!     /// A SHA-256 hash of the contents of `signed_region`.
//!     signed_region_hash: [u8; 256 / 8],
//! }
//! ```
//!
//! The FPM is not specified as part of Cerberus; it is a `manticore`-specific
//! manifest type that plays a role similar to that of a Cerberus PFM.
//!
//! [`Manifest`]: ../struct.Manifest.html

use core::convert::TryInto;
use core::mem::size_of;

use arrayvec::ArrayVec;

use crate::crypto::sha256;
use crate::hardware::FlashPtr;
use crate::hardware::FlashSlice;
use crate::io::Read as _;
use crate::manifest::read_zerocopy;
use crate::manifest::Manifest;
use crate::manifest::ParseError;

/// A Firmware Platform Manifest (FPM), describing valid states for platform
/// firmware storage.
///
/// See the [module documentation](index.html) for more information.
pub struct Fpm<'m> {
    // TODO: We should pull `4` out into a generic paramter at some point, but
    // it's unlikely that we'll need more than `4`.
    versions: ArrayVec<[FwVersion<'m>; 4]>,
}

/// A firmware version descriptor.
///
/// A `FwVersion` describes an allowed configuration of a particular storage
/// device, which contains firmware and non-volatile storage for the host
/// platform that `manticore` protects.
///
/// A `FwVersion` divides the storage device's address range into three
/// non-contiguous regions:
/// - The "signed" region, which contains firmware code. It is read-only, and
///   its contents are expected to hash to the signed_region_hash` included in
///   the version descriptor.
/// - The "write" region, which is the host's non-volatile storage region.
///   It is readable and writeable, and no policy expectations are placed on
///   its contents, since they can change arbitrarially from boot to boot.
/// - The "unused" region, which is everything not explicitly in the signed or
///   write regions. every byte therein must be uniformly equal to the
///   `blank_byte` value.
///
/// See the [module documentation](index.html) for more information.
pub struct FwVersion<'m> {
    /// The region, in a storage device, where this firmware's version number
    /// would be stored. To check that this is the firmware version loaded into
    /// the storage device, the value at this address should be compared with
    /// `version_id`.
    pub version_region: FlashSlice,
    /// This firmware's version string.
    pub version: &'m [u8],

    /// The "signed" region, represented as a list of slices in a storage
    /// device.
    pub signed_region: &'m [FlashSlice],
    /// The "write" region, represented as a list of slices in a storage device.
    pub write_region: &'m [FlashSlice],
    /// The "unused region blank byte". Every byte in the unused region is
    /// expected to have this value.
    pub blank_byte: u8,

    /// The SHA-256 hash of the "signed" region, computed by hashing together
    /// all the bytes in the slices in the `signed_region` list, in order.
    pub signed_region_hash: &'m sha256::Digest,
}

impl<'m> Fpm<'m> {
    /// Parse an `Fpm` out of a parsed and verified `Manifest`.
    pub fn parse(manifest: Manifest<'m>) -> Result<Self, ParseError> {
        let mut body = manifest.body();
        let mut fpm = Self {
            versions: ArrayVec::new(),
        };

        let fw_count = body.read_le::<u32>()?;
        for _ in 0..fw_count {
            let version_addr = body.read_le::<u32>()?;
            let signed_region_count = body.read_le::<u16>()?;
            let write_region_count = body.read_le::<u16>()?;
            let blank_byte = body.read_le::<u8>()?;
            let version_len = body.read_le::<u8>()?;
            let version = body.read_bytes(version_len as usize)?;
            // Re-align to four bytes, since the following lists are aligned as
            // such.
            let _ = body.read_bytes(body.as_ptr().align_offset(4))?;

            // TODO: Verify that these slices are sorted!
            let signed_region =
                read_zerocopy(&mut body, signed_region_count as usize)?;
            let write_region =
                read_zerocopy(&mut body, write_region_count as usize)?;

            let signed_region_hash = body
                .read_bytes(size_of::<sha256::Digest>())?
                .try_into()
                .map_err(|_| ParseError::OutOfRange)?;

            fpm.versions
                .try_push(FwVersion {
                    version_region: FlashSlice {
                        ptr: FlashPtr {
                            address: version_addr,
                        },
                        len: version_len as u32,
                    },
                    version,
                    signed_region,
                    write_region,
                    blank_byte,
                    signed_region_hash,
                })
                .map_err(|_| ParseError::OutOfRange)?;
        }

        Ok(fpm)
    }

    /// Returns an iterator over the allowed firmware versions recorded in this
    /// `Fpm`.
    pub fn versions(&self) -> impl Iterator<Item = &FwVersion> {
        self.versions.iter()
    }
}
