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
//! [`Container`] does. That signature is extended to encompass the
//! signed regions through the signed region hash.
//!
//! An FPM can be used to verify that a storage device conforms to the the
//! partitioning requirements described above.
//!
//! The FPM is not specified as part of Cerberus; it is a Manticore-specific
//! manifest type that plays a role similar to that of a Cerberus PFM.
//!
//! [`Container`]: ../container/struct.Container.html
//!
//! # Wire Format
//!
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

use core::convert::TryInto;
use core::mem::size_of;

use arrayvec::ArrayVec;

use crate::crypto::sha256;
use crate::hardware::FlashSlice;
use crate::io;
use crate::io::Read as _;
use crate::manifest::container::Container;
use crate::manifest::read_zerocopy;
use crate::manifest::take_bytes;
use crate::manifest::Error;
use crate::mem::cow::Cow;

#[cfg(all(feature = "inject-alloc", feature = "serde"))]
use serde::{Deserialize, Deserializer, Serialize};

/// A Firmware Platform Manifest (FPM), describing valid states for platform
/// firmware storage.
///
/// See the [module documentation](index.html) for more information.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Fpm<'m> {
    // TODO: We should pull `4` out into a generic paramter at some point, but
    // it's unlikely that we'll need more than `4`.
    versions: ArrayVec<[FwVersion<'m>; 4]>,
}

#[cfg(all(feature = "inject-alloc", feature = "serde"))]
impl<'de: 'm, 'm> Deserialize<'de> for Fpm<'m> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut fpm = Self {
            versions: ArrayVec::new(),
        };
        let versions = Vec::<_>::deserialize(deserializer)?;
        if versions.len() >= 4 {
            return Err(serde::de::Error::invalid_length(versions.len(), &"4"));
        }
        for version in versions {
            fpm.versions.push(version);
        }
        Ok(fpm)
    }
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
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(
    all(feature = "inject-alloc", feature = "serde"),
    derive(Serialize, Deserialize)
)]
pub struct FwVersion<'m> {
    /// The region, in a storage device, where this firmware's version number
    /// would be stored. To check that this is the firmware version loaded into
    /// the storage device, the value at this address should be compared with
    /// `version_id`.
    pub version_region: FlashSlice,
    /// This firmware's version string.
    #[cfg_attr(
        all(feature = "inject-alloc", feature = "serde"),
        serde(borrow)
    )]
    pub version: Cow<'m, [u8]>,

    /// The "signed" region, represented as a list of slices in a storage
    /// device.
    pub signed_region: Cow<'m, [FlashSlice]>,
    /// The "write" region, represented as a list of slices in a storage device.
    pub write_region: Cow<'m, [FlashSlice]>,
    /// The "unused region blank byte". Every byte in the unused region is
    /// expected to have this value.
    pub blank_byte: u8,

    /// The SHA-256 hash of the "signed" region, computed by hashing together
    /// all the bytes in the slices in the `signed_region` list, in order.
    #[cfg_attr(
        all(feature = "inject-alloc", feature = "serde"),
        serde(borrow)
    )]
    pub signed_region_hash: Cow<'m, sha256::Digest>,
}

impl<'m> Fpm<'m> {
    /// Parse an `Fpm` out of a parsed and verified `Manifest`.
    pub fn parse(container: Container<'m>) -> Result<Self, Error> {
        let mut body = container.body();
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
            let version = take_bytes(&mut body, version_len as usize)?;
            // Re-align to four bytes, since the following lists are aligned as
            // such.
            let align = body.as_ptr().align_offset(4);
            let _ = take_bytes(&mut body, align)?;

            // TODO: Verify that these slices are sorted!
            let signed_region =
                read_zerocopy(&mut body, signed_region_count as usize)?;
            let write_region =
                read_zerocopy(&mut body, write_region_count as usize)?;

            let signed_region_hash =
                take_bytes(&mut body, size_of::<sha256::Digest>())?
                    .try_into()
                    .map_err(|_| Error::OutOfRange)?;

            fpm.versions
                .try_push(FwVersion {
                    version_region: FlashSlice::new(
                        version_addr,
                        version_len as u32,
                    ),
                    version: Cow::Borrowed(version),
                    signed_region: Cow::Borrowed(signed_region),
                    write_region: Cow::Borrowed(write_region),
                    blank_byte,
                    signed_region_hash: Cow::Borrowed(signed_region_hash),
                })
                .map_err(|_| Error::OutOfRange)?;
        }

        Ok(fpm)
    }

    /// Serializes this `Fpm` into `out`.
    pub fn unparse(&self, mut out: impl io::Write) -> Result<(), Error> {
        out.write_le(self.versions.len() as u32)?;
        for version in self.versions() {
            out.write_le(version.version_region.ptr.address)?;

            let signed_len: u16 = version
                .signed_region
                .len()
                .try_into()
                .map_err(|_| Error::OutOfRange)?;
            out.write_le(signed_len)?;

            let write_len: u16 = version
                .write_region
                .len()
                .try_into()
                .map_err(|_| Error::OutOfRange)?;
            out.write_le(write_len)?;

            out.write_le(version.blank_byte)?;

            let version_len: u8 = version
                .version
                .len()
                .try_into()
                .map_err(|_| Error::OutOfRange)?;
            out.write_le(version_len)?;
            out.write_bytes(&*version.version)?;
            // Re-align to four bytes. It's only a matter of making sure that
            // `version`, plus the two previous bytes, are aligned.
            let misalign = (4 - (version.version.len() + 2) % 4) % 4;
            for _ in 0..misalign {
                out.write_le(0u8)?;
            }

            for slice in version.signed_region.iter() {
                out.write_le(slice.ptr.address)?;
                out.write_le(slice.len)?;
            }
            for slice in version.write_region.iter() {
                out.write_le(slice.ptr.address)?;
                out.write_le(slice.len)?;
            }
            out.write_bytes(&*version.signed_region_hash)?;
        }
        Ok(())
    }

    /// Returns an iterator over the allowed firmware versions recorded in this
    /// `Fpm`.
    pub fn versions(&self) -> impl Iterator<Item = &FwVersion> {
        self.versions.iter()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::manifest::container::test::make_rsa_engine;
    use crate::manifest::container::Container;
    use crate::manifest::container::Containerizer;
    use crate::manifest::container::Metadata;
    use crate::manifest::ManifestType;

    #[test]
    fn round_trip() {
        let mut buf = vec![0; 1024];
        let mut buf2 = vec![0; 1024];

        let mut fpm = Fpm {
            versions: ArrayVec::new(),
        };
        // NOTE: writing this as a constant forces const-promotion of the
        // slice definitions inside.
        const VERSION: FwVersion = FwVersion {
            version_region: FlashSlice::new(0x22, 5),
            version: Cow::Borrowed(&[1, 2, 3, 4, 5]),
            signed_region: Cow::Borrowed(&[
                FlashSlice::new(0x0, 256),
                FlashSlice::new(0x200, 55),
            ]),
            write_region: Cow::Borrowed(&[FlashSlice::new(0x400, 100)]),
            blank_byte: 0xee,
            signed_region_hash: Cow::Borrowed(&[0xa5; 32]),
        };
        fpm.versions.push(VERSION);

        let (mut rsa, mut signer) = make_rsa_engine();
        let mut builder = Containerizer::new(&mut buf)
            .unwrap()
            .with_type(ManifestType::Fpm)
            .unwrap()
            .with_metadata(&Metadata { version_id: 0x1 })
            .unwrap();
        fpm.unparse(&mut builder).unwrap();
        let manifest_bytes = builder.sign(&mut signer).unwrap();

        let manifest =
            Container::parse_and_verify(manifest_bytes, &mut rsa).unwrap();
        let fpm2 = Fpm::parse(manifest).unwrap();
        assert_eq!(fpm, fpm2);

        let mut builder = Containerizer::new(&mut buf2)
            .unwrap()
            .with_type(ManifestType::Fpm)
            .unwrap()
            .with_metadata(&Metadata { version_id: 0x1 })
            .unwrap();
        fpm2.unparse(&mut builder).unwrap();
        let manifest_bytes2 = builder.sign(&mut signer).unwrap();
        assert_eq!(manifest_bytes, manifest_bytes2);

        let manifest =
            Container::parse_and_verify(manifest_bytes2, &mut rsa).unwrap();
        let fpm3 = Fpm::parse(manifest).unwrap();
        assert_eq!(fpm, fpm3);
    }
}
