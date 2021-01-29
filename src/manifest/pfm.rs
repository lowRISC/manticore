// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! The Platform Firmware Manifest (PFM)
//!
//! A PFM is a computer-readable policy document describing firmware which is
//! allowed to run on a device. Practically, this means that a PFM describes
//! an allowed configuration of an external storage device, such as a SPI
//! flash device. It also carries some additional metadata about the platform
//! itself.
//!
//! The PFM is designed to be readable by "random access". It is encoded as a
//! ["table of contents"](struct.Toc.html) that describes various blobs that
//! follow it; this table of contents makes it possible to pull different parts
//! of the PFM out in arbitrary order. The PFM also contains hashes for
//! ensuring that all data read from flash is protected by the original
//! signature check.
//!
//! The [`Pfm`] type is the entry-point for this module.
//!
//! [`Pfm`]: struct.Pfm.html

use core::mem;

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;

use crate::crypto::sha256;
use crate::hardware::flash::Flash;
use crate::hardware::flash::Region;
use crate::io::Read as _;
use crate::manifest::container::Container;
use crate::manifest::container::HashType;
use crate::manifest::container::TocEntry;
use crate::manifest::provenance;
use crate::manifest::Error;
use crate::manifest::Manifest;
use crate::manifest::ManifestType;
use crate::mem::misalign_of;
use crate::mem::Arena;

use crate::mem::ArenaExt as _;
use crate::protocol::wire::WireEnum as _;

wire_enum! {
    /// A PFM element type.
    pub enum ElementType: u8 {
      /// A `FlashDevice` defines global information pertinent to the entire
      /// flash device a particular PFM describes.
      FlashDevice = 0x00,

      /// A list of firmware versions (i.e., contents of flash) allowed by
      /// policy on the flash device a particular PFM describes.
      AllowableFw = 0x01,

      /// A firmware version, as a subelement of an `AllowableFw`.
      FwVersion = 0x02,

      /// A bytestring identifier for the platform that this PFM describes.
      PlatformId = 0x03,
    }
}

/// A Platform Firmware Manifest.
///
/// This type provides functions for parsing a PFM's table of contents and
/// using it to extract other portions of the PFM.
///
/// This type only maintains the TOC in memory for book-keeping.
pub struct Pfm<'pfm, Flash> {
    container: Container<'pfm, Self, Flash, provenance::Signed>,
}

impl<F> Manifest for Pfm<'_, F> {
    type ElementType = ElementType;
    const TYPE: ManifestType = ManifestType::Pfm;

    fn min_version(_: ElementType) -> u8 {
        0
    }
}

impl<'pfm, F: Flash> Pfm<'pfm, F> {
    /// Creates a new PFM handle using the given `Container`.
    pub fn new(
        container: Container<'pfm, Self, F, provenance::Signed>,
    ) -> Self {
        Pfm { container }
    }

    /// Extracts the Platform ID from this PFM, allocating it onto the provided
    /// arena. Returns `None` if the Platform ID is missing.
    ///
    /// This function will also verify the hash of the Platform ID, if one is
    /// present.
    pub fn platform_id(
        &self,
        sha: &impl sha256::Builder,
        arena: &'pfm impl Arena,
    ) -> Result<Option<PlatformId<'pfm>>, Error> {
        let entry = match self
            .container
            .toc()
            .entries()
            .find(|e| e.element_type() == ElementType::PlatformId)
        {
            Some(x) => x,
            None => return Ok(None),
        };
        if entry.region().len < 4 {
            return Err(Error::OutOfRange);
        }

        let data =
            self.container
                .flash()
                .read_direct(entry.region(), arena, 1)?;
        let (header, rest) = data.split_at(4);
        let len = header[0] as usize;
        if rest.len() < len {
            return Err(Error::OutOfRange);
        }

        let id = &rest[..len];

        if let Some(expected) = entry.hash() {
            let mut hash = [0; 32];
            sha.hash_contiguous(&data, &mut hash)?;
            if &hash != expected {
                return Err(Error::SignatureFailure);
            }
        }

        Ok(Some(PlatformId { _data: data, id }))
    }

    /// Extracts the `FlashDeviceInfo` element from this PFM.
    ///
    /// This function will also verify the hash of the `FlashDeviceInfo` if one
    /// is present.
    pub fn flash_device_info(
        &self,
        sha: &impl sha256::Builder,
        arena: &'pfm impl Arena,
    ) -> Result<Option<FlashDeviceInfo<'pfm>>, Error> {
        let entry = match self
            .container
            .toc()
            .entries()
            .find(|e| e.element_type() == ElementType::FlashDevice)
        {
            Some(x) => x,
            None => return Ok(None),
        };
        if entry.region().len < 4 {
            return Err(Error::OutOfRange);
        }

        let data =
            self.container
                .flash()
                .read_direct(entry.region(), arena, 1)?;
        let blank_byte = data[0];

        if let Some(expected) = entry.hash() {
            let mut hash = [0; 32];
            sha.hash_contiguous(&data, &mut hash)?;
            if &hash != expected {
                return Err(Error::SignatureFailure);
            }
        }

        Ok(Some(FlashDeviceInfo {
            _data: data,
            blank_byte,
        }))
    }

    /// Returns an iterator over the `AllowableFw` elements of this PFM.
    ///
    /// The returned values only contain the `Toc` information for the entry,
    /// allowing the user to lazily select which entries to read from flash.
    pub fn allowable_fws(
        &self,
    ) -> impl Iterator<Item = AllowableFwEntry<'_, 'pfm, F>> + '_ {
        self.container
            .toc()
            .entries()
            .filter(|e| e.element_type() == ElementType::AllowableFw)
            .map(move |entry| AllowableFwEntry { pfm: self, entry })
    }
}

/// An identifier for the platform a PFM is for.
pub struct PlatformId<'pfm> {
    _data: &'pfm [u8],
    id: &'pfm [u8],
}

impl<'pfm> PlatformId<'pfm> {
    /// Returns the byte-string identifier that represents the platform this
    /// PFM is for.
    pub fn id_string(&self) -> &'pfm [u8] {
        self.id
    }
}

/// A descriptor for a flash device protected by a PFM.
///
/// Note that this is distinct from the flash device that the PFM itself is
/// stored in.
pub struct FlashDeviceInfo<'pfm> {
    _data: &'pfm [u8],
    blank_byte: u8,
}

impl<'pfm> FlashDeviceInfo<'pfm> {
    /// Returns the "blank byte" for this `FlashDevice`.
    ///
    /// The "blank byte" is the byte value that unallocated regions in the
    /// device must be filled with, to ensure that they do not contain
    /// malicious information.
    pub fn blank_byte(&self) -> u8 {
        self.blank_byte
    }
}

/// An "allowable firmware" element entry in a PFM's `Toc`.
///
/// This type allows for lazily reading the [`AllowableFw`] described by this
/// entry, as obtained from [`Pfm::allowable_firmware()`].
///
/// [`AllowableFw`]: struct.AllowableFw.html
/// [`Pfm::allowable_firmware()`]: struct.Pfm.html#method.allowable_firmware
pub struct AllowableFwEntry<'a, 'pfm, Flash> {
    pfm: &'a Pfm<'pfm, Flash>,
    entry: TocEntry<'a, 'pfm, Pfm<'pfm, Flash>>,
}

impl<'a, 'pfm, F: Flash> AllowableFwEntry<'a, 'pfm, F> {
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pfm, Pfm<'pfm, F>> {
        self.entry
    }

    /// Reads the contents of this element into memory, verifying its hash
    /// and potentially allocating it on `arena`.
    pub fn read(
        self,
        sha: &impl sha256::Builder,
        arena: &'pfm impl Arena,
    ) -> Result<AllowableFw<'a, 'pfm, F>, Error> {
        let data = self.pfm.container.flash().read_direct(
            self.entry.region(),
            arena,
            1,
        )?;
        let (header, rest) = data.split_at(4);
        let fw_count = header[0] as usize;
        let id_len = header[1] as usize;
        // FIXME: Don't drop this on the ground.
        let _flags = header[2];

        if rest.len() < id_len {
            return Err(Error::OutOfRange);
        }
        let fw_id = &rest[..id_len];

        if let Some(expected) = self.entry.hash() {
            let mut hash = [0; 32];
            sha.hash_contiguous(&data, &mut hash)?;
            if &hash != expected {
                return Err(Error::SignatureFailure);
            }
        }

        Ok(AllowableFw {
            entry: self,
            _data: data,
            fw_count,
            fw_id,
        })
    }
}

/// An "allowable firmware" element from a PFM, describing how platform
/// firmware is expected to be laid out in memory.
///
/// To obtain a value of this type, see [`Pfm::allowable_firmware()`] and
/// [`AllowableFwEntry::read()`].
///
/// [`Pfm::allowable_firmware()`]: struct.Pfm.html#method.allowable_firmware
/// [`AllowableFwEntry::read()`]: struct.AllowableFwEntry.html#method.read
pub struct AllowableFw<'a, 'pfm, Flash> {
    entry: AllowableFwEntry<'a, 'pfm, Flash>,
    _data: &'pfm [u8],
    fw_count: usize,
    fw_id: &'pfm [u8],
}

impl<'a, 'pfm, F: Flash> AllowableFw<'a, 'pfm, F> {
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pfm, Pfm<'pfm, F>> {
        self.entry.entry
    }

    /// Returns the number of specific, allowable firmware images associated
    /// with this element.
    ///
    /// Note that this may be inconsistent with the number of children actually
    /// encoded in the PFM.
    pub fn firmware_count(&self) -> usize {
        self.fw_count
    }

    /// Returns the firmware ID string for this element.
    pub fn firmware_id(&self) -> &'pfm [u8] {
        self.fw_id
    }

    /// Returns an iterator over the `FwVersion` subelements of this `AllowableFw`.
    ///
    /// The returned values only contain the `Toc` information for the entry,
    /// allowing the user to lazily select which entries to read from flash.
    pub fn firmware_versions(
        &self,
    ) -> impl Iterator<Item = FwVersionEntry<'_, 'pfm, F>> + '_ {
        self.entry()
            .children()
            .filter(|e| e.element_type() == ElementType::FwVersion)
            .map(move |entry| FwVersionEntry {
                version: self,
                entry,
            })
    }
}

/// A "firmware version" element entry in a PFM's `Toc`.
///
/// This type allows for lazily reading the [`FwVersion`] described by this
/// entry, as obtained from [`AlloawbleFw::firmware_versions()`].
///
/// [`FwVersion`]: struct.FwVersion.html
/// [`AllowableFw::firmware_versions()`]: struct.AllowableFw.html#method.firmware_versions
pub struct FwVersionEntry<'a, 'pfm, Flash> {
    version: &'a AllowableFw<'a, 'pfm, Flash>,
    entry: TocEntry<'a, 'pfm, Pfm<'pfm, Flash>>,
}

impl<'a, 'pfm, F: Flash> FwVersionEntry<'a, 'pfm, F> {
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pfm, Pfm<'pfm, F>> {
        self.entry
    }

    /// Reads the contents of this element into memory, verifying its hash
    /// and potentially allocating it on `arena`.
    pub fn read(
        self,
        sha: &impl sha256::Builder,
        arena: &'pfm impl Arena,
    ) -> Result<FwVersion<'a, 'pfm, F>, Error> {
        #[rustfmt::skip]
        let data = self.version.entry.pfm.container.flash().read_direct(
            self.entry.region(),
            arena,
            mem::align_of::<u32>(),
        )?;
        if let Some(expected) = self.entry.hash() {
            let mut hash = [0; 32];
            sha.hash_contiguous(data, &mut hash)?;
            if &hash != expected {
                return Err(Error::SignatureFailure);
            }
        }

        let mut buf = data;
        let image_count = buf.read_le::<u8>()? as usize;
        let rw_count = buf.read_le::<u8>()? as usize;
        let version_len = buf.read_le::<u8>()? as usize;
        let _ = buf.read_le::<u8>()?;
        let version_addr = buf.read_le::<u32>()?;

        if buf.len() < version_len {
            return Err(Error::OutOfRange);
        }
        let (version_str, mut buf) = buf.split_at(version_len);

        // Align back to 4-byte boundary.
        buf = &buf[misalign_of(buf.as_ptr() as usize, 4)..];

        let rw_len = mem::size_of::<RwRegion>() * rw_count;
        let (rw_bytes, unparsed_image_regions) = buf.split_at(rw_len);
        // NOTE: This cannot panic, since it checks for alignment (4-byte) and
        // size, which have already been explicitly checked above.
        let rw_regions = LayoutVerified::<_, [RwRegion]>::new_slice(rw_bytes)
            .unwrap()
            .into_slice();
        for rw in rw_regions {
            if rw.start_addr > rw.end_addr {
                return Err(Error::OutOfRange);
            }
        }

        let image_region_offsets = arena.alloc_slice::<u32>(image_count)?;
        if image_count > 0 {
            // FIXME: we don't need to actually track this "first" offset.
            image_region_offsets[0] = 0;
            for i in 0..image_count {
                let rest =
                    &unparsed_image_regions[image_region_offsets[i] as usize..];
                let (header, rest) =
                    match LayoutVerified::<_, FwRegionHeader>::new_from_prefix(
                        rest,
                    ) {
                        Some(h) => h,
                        None => return Err(Error::OutOfRange),
                    };
                // FIXME: we don't deal with hash types that aren't SHA-256.
                if header.hash_type != HashType::Sha256.to_wire_value() {
                    return Err(Error::OutOfRange);
                }

                let ranges_len = header.region_count as usize
                    * mem::size_of::<FwRegionRange>();
                if rest.len() < ranges_len {
                    return Err(Error::OutOfRange);
                }
                let ranges =
                    match LayoutVerified::<_, [FwRegionRange]>::new_slice(
                        &rest[..ranges_len],
                    ) {
                        Some(h) => h,
                        None => return Err(Error::OutOfRange),
                    };
                for r in &*ranges {
                    if r.start_addr > r.end_addr {
                        return Err(Error::OutOfRange);
                    }
                }

                if i != image_count - 1 {
                    image_region_offsets[i + 1] = image_region_offsets[i]
                        + ranges_len as u32
                        + mem::size_of::<FwRegionHeader>() as u32;
                }
            }
        }

        Ok(FwVersion {
            entry: self,
            _data: data,
            version_addr,
            version_str,
            rw_regions,
            image_region_offsets,
            unparsed_image_regions,
        })
    }
}

/// A "firmware version" element from a PFM.
///
/// To obtain a value of this type, see [`AwllowableFw::firmware_versions()`] and
/// [`FwVersionEntry::read()`].
///
/// [`AllowableFw::firmware_versions()`]: struct.AllowableFw.html#method.firmware_versions
/// [`FwVersion::read()`]: struct.FwVersion.html#method.read
pub struct FwVersion<'a, 'pfm, Flash> {
    #[allow(unused)]
    entry: FwVersionEntry<'a, 'pfm, Flash>,
    _data: &'pfm [u8],
    version_addr: u32,
    version_str: &'pfm [u8],
    rw_regions: &'pfm [RwRegion],
    // TODO: Can we get away with u16 here?
    image_region_offsets: &'pfm [u32],
    unparsed_image_regions: &'pfm [u8],
}

impl<'pfm, F> FwVersion<'_, 'pfm, F> {
    /// Returns the flash region in which this `FwVersion`'s version string
    /// would be located, and the expected value of that region.
    pub fn version(&self) -> (Region, &'pfm [u8]) {
        (
            Region::new(self.version_addr, self.version_str.len() as u32),
            self.version_str,
        )
    }

    // NOTE: We do not provide direct access to the rw_regions slice, to keep
    // its contiguous-ness an implementation detail.

    /// Returns the number of individual read-write regions in this
    /// `FwVersion`.
    pub fn rw_count(&self) -> usize {
        self.rw_regions.len()
    }

    /// Returns the `idx`th read-write region, if there is one.
    pub fn rw_region(&self, idx: usize) -> Option<&RwRegion> {
        self.rw_regions.get(idx)
    }

    /// Returns an iterator over this `FwVersion`'s read-write regions.
    pub fn rw_regions(&self) -> impl Iterator<Item = &RwRegion> + '_ {
        self.rw_regions.iter()
    }

    /// Returns the number of individual image regions in this
    /// `FwVersion`.
    pub fn image_count(&self) -> usize {
        self.image_region_offsets.len()
    }

    /// Returns the `idx`th image region, if there is one.
    pub fn image_region(&self, idx: usize) -> Option<FwRegion<'_>> {
        let start = *self.image_region_offsets.get(idx)? as usize;
        let end = self
            .image_region_offsets
            .get(idx + 1)
            .map(|x| *x as usize)
            .unwrap_or(self.unparsed_image_regions.len());

        let bytes = &self.unparsed_image_regions[start..end];

        // Length and alignment were checked in FwVersionEntry::read(), so
        // this cannot panic.
        let (header, bytes) =
            LayoutVerified::<_, FwRegionHeader>::new_from_prefix(bytes)
                .unwrap();
        let ranges =
            LayoutVerified::<_, [FwRegionRange]>::new_slice(bytes).unwrap();
        debug_assert!(ranges.len() == header.region_count as usize);

        Some(FwRegion {
            header: header.into_ref(),
            ranges: ranges.into_slice(),
        })
    }

    /// Returns an iterator over this `FwVersion`'s image regions.
    pub fn image_regions(&self) -> impl Iterator<Item = FwRegion<'_>> + '_ {
        (0..self.image_count()).map(move |n| self.image_region(n).unwrap())
    }
}

wire_enum! {
    /// A policy for responding to verification failure in a read-write region.
    ///
    /// Cerberus currently does not fully specify what these policies mean
    /// precisely, nor what failure mode they should be enacted with respect
    /// to.
    pub enum RwFailurePolicy: u8 {
        /// Do nothing.
        DoNothing = 0b00,
        /// Restore the region from write-only memory.
        RestoreFromRo = 0b01,
        /// Erase the region.
        Erase = 0b10,
    }
}

/// A read-write region within a [`FwVersion`].
///
/// This region is not hashed or protected in any way, and both reads and
/// writes to it are permitted; it is effectively a scratch area.
///
/// [`FwVersion`]: struct.FwVersion.html
#[derive(FromBytes, AsBytes)]
#[repr(C)]
pub struct RwRegion {
    flags: u8,
    _reserved: [u8; 3],
    start_addr: u32,
    end_addr: u32,
}

impl RwRegion {
    /// Returns a policy to enact "on failure" (currently underspecified).
    pub fn failure_policy(&self) -> Option<RwFailurePolicy> {
        RwFailurePolicy::from_wire_value(self.flags & 0b11)
    }

    /// Returns the actual flash region described by this region.
    pub fn region(&self) -> Region {
        Region::new(self.start_addr, self.end_addr - self.start_addr)
    }
}

/// An image region within a [`FwVersion`].
///
/// This region is protected by a hash, and only reads to it are permitted.
/// Currently, Manticore only supports SHA-256 hashes here.
///
/// [`FwVersion`]: struct.FwVersion.html
pub struct FwRegion<'a> {
    header: &'a FwRegionHeader,
    ranges: &'a [FwRegionRange],
}

#[derive(FromBytes)]
#[repr(C)]
struct FwRegionHeader {
    hash_type: u8,
    region_count: u8,
    flags: u8,
    _reserved: u8,
    image_hash: sha256::Digest,
}

#[derive(FromBytes)]
#[repr(C)]
struct FwRegionRange {
    start_addr: u32,
    end_addr: u32,
}

impl FwRegion<'_> {
    /// Returns whether this region must be validated on boot, rather than just
    /// when loading a new firmware update.
    pub fn must_validate_on_boot(&self) -> bool {
        (self.header.flags & 1) == 1
    }

    /// Returns the hash that this region is expected to conform to.
    pub fn image_hash(&self) -> &sha256::Digest {
        &self.header.image_hash
    }

    /// Returns the number of flash regions that actually make up this image
    /// region.
    pub fn region_count(&self) -> usize {
        self.header.region_count as usize
    }

    /// Returns the `idx`th flash region in this image region, if there is one.
    pub fn region(&self, idx: usize) -> Option<Region> {
        let range = self.ranges.get(idx)?;
        Some(Region::new(
            range.start_addr,
            range.end_addr - range.start_addr,
        ))
    }

    /// Returns an iterator over the flash regions that make up this image
    /// region.
    pub fn regions(&self) -> impl Iterator<Item = Region> + '_ {
        (0..self.region_count()).map(move |n| self.region(n).unwrap())
    }
}

#[cfg(test)]
#[allow(unused)]
mod test {
    use super::*;

    use crate::crypto::ring;
    use crate::crypto::sha256::Builder as _;
    use crate::hardware::flash::Ram;
    use crate::io::Write as _;
    use crate::manifest::container::test::make_rsa_engine;
    use crate::manifest::container::Container;
    use crate::manifest::container::Metadata;
    use crate::manifest::owned;
    use crate::manifest::ManifestType;
    use crate::mem::BumpArena;
    use crate::mem::OutOfMemory;

    use serde_json::from_str;

    #[test]
    fn empty() {
        let sha = ring::sha256::Builder::new();
        let (mut rsa, mut signer) = make_rsa_engine();

        #[rustfmt::skip]
        let pfm: owned::Pfm = from_str(r#"{
            "version_id": 42,
            "elements": []
        }"#).unwrap();
        let bytes = Ram(pfm.sign(0x0, &sha, &mut signer).unwrap());

        let container = Container::parse_and_verify(
            &bytes,
            &sha,
            &mut rsa,
            &OutOfMemory,
            &OutOfMemory,
        )
        .unwrap();
        let pfm = Pfm::new(container);

        assert!(pfm.platform_id(&sha, &OutOfMemory).unwrap().is_none());
        assert!(pfm.flash_device_info(&sha, &OutOfMemory).unwrap().is_none());
        assert_eq!(pfm.allowable_fws().count(), 0);
    }

    #[test]
    fn platform_id() {
        let sha = ring::sha256::Builder::new();
        let (mut rsa, mut signer) = make_rsa_engine();

        #[rustfmt::skip]
        let pfm: owned::Pfm = from_str(r#"{
            "version_id": 42,
            "elements": [{ "platform_id": "my pfm" }]
        }"#).unwrap();
        let bytes = Ram(pfm.sign(0x0, &sha, &mut signer).unwrap());

        let container = Container::parse_and_verify(
            &bytes,
            &sha,
            &mut rsa,
            &OutOfMemory,
            &OutOfMemory,
        )
        .unwrap();
        let pfm = Pfm::new(container);

        let id = pfm.platform_id(&sha, &OutOfMemory).unwrap().unwrap();
        assert_eq!(id.id_string(), b"my pfm");
    }

    #[test]
    fn fw_versions() {
        let sha = ring::sha256::Builder::new();
        let (mut rsa, mut signer) = make_rsa_engine();

        #[rustfmt::skip]
        let pfm: owned::Pfm = from_str(r#"{
            "version_id": 42,
            "elements": [
                { "blank_byte": "0xff" },
                {
                    "version_count": 1,
                    "firmware_id": "my cool firmware",
                    "flags": "0b10101010",
                    "hashed": false,
                    "children": [{
                        "version_addr": "0x12345678",
                        "version_str": "ver-1.2.2",
                        "rw_regions": [{
                            "flags": "0b00110011",
                            "region": {
                                "offset": "0x00008000",
                                "len": "0x8000"
                            }
                        }],
                        "image_regions": [
                            {
                                "flags": "0o7",
                                "hash_type": "Sha256",
                                "hash": [
                                    42, 42, 42, 42, 42, 42, 42, 42,
                                    42, 42, 42, 42, 42, 42, 42, 42,
                                    42, 42, 42, 42, 42, 42, 42, 42,
                                    42, 42, 42, 42, 42, 42, 42, 42
                                ],
                                "regions": [
                                    { "offset": "0x10000", "len": "0x1000" },
                                    { "offset": "0x18000", "len": "0x800" }
                                ]
                            },
                            {
                                "flags": 0,
                                "hash_type": "Sha256",
                                "hash": [
                                    77, 77, 77, 77, 77, 77, 77, 77,
                                    77, 77, 77, 77, 77, 77, 77, 77,
                                    77, 77, 77, 77, 77, 77, 77, 77,
                                    77, 77, 77, 77, 77, 77, 77, 77
                                ],
                                "regions": [
                                    { "offset": "0x20000", "len": "0x800" },
                                    { "offset": "0x28000", "len": "0x1000" }
                                ]
                            }
                        ]
                    }]
                }
            ]
        }"#).unwrap();
        let bytes = Ram(pfm.sign(0x0, &sha, &mut signer).unwrap());

        let container = Container::parse_and_verify(
            &bytes,
            &sha,
            &mut rsa,
            &OutOfMemory,
            &OutOfMemory,
        )
        .unwrap();
        let pfm = Pfm::new(container);

        let device =
            pfm.flash_device_info(&sha, &OutOfMemory).unwrap().unwrap();
        assert_eq!(device.blank_byte(), 0xff);

        let mut allowed_fws = pfm.allowable_fws().map(Some).collect::<Vec<_>>();
        assert_eq!(allowed_fws.len(), 1);

        let allowed = allowed_fws[0]
            .take()
            .unwrap()
            .read(&sha, &OutOfMemory)
            .unwrap();
        assert_eq!(allowed.firmware_id(), b"my cool firmware");

        let mut arena = [0; 256];
        let arena = BumpArena::new(&mut arena);
        let mut versions =
            allowed.firmware_versions().map(Some).collect::<Vec<_>>();
        assert_eq!(allowed_fws.len(), 1);

        let fw = versions[0].take().unwrap().read(&sha, &arena).unwrap();
        assert_eq!(
            fw.version(),
            (Region::new(0x12345678, 9), b"ver-1.2.2".as_ref())
        );
        assert_eq!(fw.rw_count(), 1);
        assert_eq!(fw.image_count(), 2);

        let rws = fw.rw_regions().collect::<Vec<_>>();
        assert_eq!(rws.len(), 1);
        assert_eq!(rws[0].region(), Region::new(0x8000, 0x8000));

        let imgs = fw.image_regions().collect::<Vec<_>>();
        assert_eq!(imgs.len(), 2);

        assert_eq!(imgs[0].image_hash(), &[42; 32]);
        assert_eq!(imgs[0].region_count(), 2);
        assert_eq!(imgs[0].region(0), Some(Region::new(0x10000, 0x1000)));
        assert_eq!(imgs[0].region(1), Some(Region::new(0x18000, 0x800)));
        assert!(imgs[0].region(2).is_none());

        assert_eq!(imgs[1].image_hash(), &[77; 32]);
        assert_eq!(imgs[1].region_count(), 2);
        assert_eq!(imgs[1].region(0), Some(Region::new(0x20000, 0x800)));
        assert_eq!(imgs[1].region(1), Some(Region::new(0x28000, 0x1000)));
        assert!(imgs[1].region(2).is_none());
    }
}
