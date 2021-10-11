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
//! The [`ParsedPfm`] type is the entry-point for this module.

use core::mem;

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;

use crate::crypto::hash;
use crate::hardware::flash::Flash;
use crate::hardware::flash::Region;
use crate::manifest::provenance;
use crate::manifest::provenance::Provenance;
use crate::manifest::Container;
use crate::manifest::Error;
use crate::manifest::Manifest;
use crate::manifest::ManifestType;
use crate::manifest::Parse;
use crate::manifest::ParsedManifest;
use crate::manifest::TocEntry;
use crate::manifest::ValidationTime;
use crate::mem::misalign_of;
use crate::mem::Arena;

use crate::mem::ArenaExt as _;
use crate::protocol::wire::WireEnum as _;

wire_enum! {
    /// A PFM element type.
    pub enum ElementType: u8 {
      /// A `FlashDevice` defines global information pertinent to the entire
      /// flash device a particular PFM describes.
      FlashDevice = 0x10,

      /// A list of firmware versions (i.e., contents of flash) allowed by
      /// policy on the flash device a particular PFM describes.
      AllowableFw = 0x11,

      /// A firmware version, as a subelement of an `AllowableFw`.
      FwVersion = 0x12,
    }
}

/// A Platform Firmware Manifest.
///
/// This type provides functions for parsing a PFM's table of contents and
/// using it to extract other portions of the PFM.
///
/// This type only maintains the TOC in memory for book-keeping.
pub struct ParsedPfm<'pfm, Flash, Provenance = provenance::Signed> {
    container: Container<'pfm, Pfm, Flash, Provenance>,
}

/// A [`Manifest`] implementation mapping onto [`ParsedPfm`], for use in generic
/// contexts.
///
/// See [`Manifest`] and [`Parse`].
pub enum Pfm {}

impl Manifest for Pfm {
    type ElementType = ElementType;
    const TYPE: ManifestType = ManifestType::Pfm;

    fn min_version(_: ElementType) -> u8 {
        0
    }
}

impl<'f, F: 'f + Flash, P> Parse<'f, F, P> for Pfm {
    type Parsed = ParsedPfm<'f, F, P>;

    fn parse(
        container: Container<'f, Self, F, P>,
    ) -> Result<Self::Parsed, Error> {
        Ok(ParsedPfm::new(container))
    }

    fn container(manifest: &Self::Parsed) -> &Container<'f, Self, F, P> {
        &manifest.container
    }

    type Guarded = ();
    fn validate(
        _manifest: &Self::Parsed,
        _when: ValidationTime,
        _args: &Self::Guarded,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<F, P> ParsedManifest for ParsedPfm<'_, F, P> {
    type Manifest = Pfm;
}

impl<'pfm, F, P> ParsedPfm<'pfm, F, P> {
    /// Creates a new PFM handle using the given `Container`.
    pub fn new(container: Container<'pfm, Pfm, F, P>) -> Self {
        ParsedPfm { container }
    }
}

impl<'pfm, F: Flash, P> ParsedPfm<'pfm, F, P>
where
    P: Provenance,
{
    /// Extracts the `FlashDeviceInfo` element from this PFM.
    ///
    /// This function will also verify the hash of the `FlashDeviceInfo` if one
    /// is present.
    pub fn flash_device_info<'a>(
        &'a self,
        hasher: &mut impl hash::Engine,
        arena: &'pfm impl Arena,
    ) -> Result<Option<FlashDeviceInfo<'a, 'pfm>>, Error> {
        let entry = match self
            .container
            .toc()
            .singleton(ElementType::FlashDevice.into())
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

        #[derive(FromBytes)]
        #[repr(C)]
        pub struct FlashDeviceHeader {
            blank_byte: u8,
            _unused: [u8; 3],
        }
        let (header, _) =
            LayoutVerified::<_, FlashDeviceHeader>::new_from_prefix(data)
                .ok_or(Error::TooShort {
                    toc_index: entry.index(),
                })?;

        if P::AUTHENTICATED {
            entry.check_hash(data, hasher)?;
        }

        Ok(Some(FlashDeviceInfo {
            _data: data,
            entry,
            blank_byte: header.blank_byte,
        }))
    }

    /// Returns an iterator over the `AllowableFw` elements of this PFM.
    ///
    /// The returned values only contain the `Toc` information for the entry,
    /// allowing the user to lazily select which entries to read from flash.
    pub fn allowable_fws(
        &self,
    ) -> impl Iterator<Item = AllowableFwEntry<'_, 'pfm, F, P>> + '_ {
        self.container
            .toc()
            .entries_of(ElementType::AllowableFw.into())
            .map(move |entry| AllowableFwEntry { pfm: self, entry })
    }
}

/// A descriptor for a flash device protected by a PFM.
///
/// Note that this is distinct from the flash device that the PFM itself is
/// stored in.
pub struct FlashDeviceInfo<'a, 'pfm> {
    _data: &'pfm [u8],
    entry: TocEntry<'a, 'pfm, Pfm>,
    blank_byte: u8,
}

impl<'a, 'pfm> FlashDeviceInfo<'a, 'pfm> {
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pfm, Pfm> {
        self.entry
    }

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
/// entry, as obtained from [`ParsedPfm::allowable_fws()`].
pub struct AllowableFwEntry<'a, 'pfm, Flash, Provenance = provenance::Signed> {
    pfm: &'a ParsedPfm<'pfm, Flash, Provenance>,
    entry: TocEntry<'a, 'pfm, Pfm>,
}

impl<'a, 'pfm, F: Flash, P> AllowableFwEntry<'a, 'pfm, F, P>
where
    P: Provenance,
{
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pfm, Pfm> {
        self.entry
    }

    /// Reads the contents of this element into memory, verifying its hash
    /// and potentially allocating it on `arena`.
    pub fn read(
        self,
        hasher: &mut impl hash::Engine,
        arena: &'pfm impl Arena,
    ) -> Result<AllowableFw<'a, 'pfm, F, P>, Error> {
        let data = self.pfm.container.flash().read_direct(
            self.entry.region(),
            arena,
            1,
        )?;

        #[derive(FromBytes)]
        #[repr(C)]
        struct AllowableFwHeader {
            fw_count: u8,
            id_len: u8,
            flags: u8,
            _unused: u8,
        }
        let (header, rest) =
            LayoutVerified::<_, AllowableFwHeader>::new_from_prefix(data)
                .ok_or(Error::TooShort {
                    toc_index: self.entry.index(),
                })?;

        let id_len = header.id_len as usize;
        if rest.len() < id_len {
            return Err(Error::TooShort {
                toc_index: self.entry.index(),
            });
        }
        let fw_id = &rest[..id_len];

        if P::AUTHENTICATED {
            self.entry.check_hash(data, hasher)?;
        }

        Ok(AllowableFw {
            entry: self,
            _data: data,
            fw_count: header.fw_count,
            fw_id,
            flags: header.flags,
        })
    }
}

/// An "allowable firmware" element from a PFM, describing how platform
/// firmware is expected to be laid out in memory.
///
/// To obtain a value of this type, see [`ParsedPfm::allowable_fws()`] and
/// [`AllowableFwEntry::read()`].
pub struct AllowableFw<'a, 'pfm, Flash, Provenance = provenance::Signed> {
    entry: AllowableFwEntry<'a, 'pfm, Flash, Provenance>,
    _data: &'pfm [u8],
    fw_count: u8,
    fw_id: &'pfm [u8],
    flags: u8,
}

impl<'a, 'pfm, F: Flash, P> AllowableFw<'a, 'pfm, F, P> {
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pfm, Pfm> {
        self.entry.entry
    }

    /// Returns the number of specific, allowable firmware images associated
    /// with this element.
    ///
    /// Note that this may be inconsistent with the number of children actually
    /// encoded in the PFM.
    pub fn firmware_count(&self) -> usize {
        self.fw_count as usize
    }

    /// Returns the firmware ID string for this element.
    pub fn firmware_id(&self) -> &'pfm [u8] {
        self.fw_id
    }

    /// Returns the raw encoded flags for this element.
    pub fn raw_flags(&self) -> u8 {
        self.flags
    }

    /// Returns an iterator over the `FwVersion` subelements of this `AllowableFw`.
    ///
    /// The returned values only contain the `Toc` information for the entry,
    /// allowing the user to lazily select which entries to read from flash.
    pub fn firmware_versions(
        &self,
    ) -> impl Iterator<Item = FwVersionEntry<'_, 'pfm, F, P>> + '_ {
        self.entry().children_of(ElementType::FwVersion.into()).map(
            move |entry| FwVersionEntry {
                version: self,
                entry,
            },
        )
    }
}

/// A "firmware version" element entry in a PFM's `Toc`.
///
/// This type allows for lazily reading the [`FwVersion`] described by this
/// entry, as obtained from [`AllowableFw::firmware_versions()`].
pub struct FwVersionEntry<'a, 'pfm, Flash, Provenance = provenance::Signed> {
    version: &'a AllowableFw<'a, 'pfm, Flash, Provenance>,
    entry: TocEntry<'a, 'pfm, Pfm>,
}

impl<'a, 'pfm, F: Flash, P> FwVersionEntry<'a, 'pfm, F, P>
where
    P: Provenance,
{
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pfm, Pfm> {
        self.entry
    }

    /// Reads the contents of this element into memory, verifying its hash
    /// and potentially allocating it on `arena`.
    pub fn read(
        self,
        hasher: &mut impl hash::Engine,
        arena: &'pfm impl Arena,
    ) -> Result<FwVersion<'a, 'pfm, F, P>, Error> {
        #[rustfmt::skip]
        let data = self.version.entry.pfm.container.flash().read_direct(
            self.entry.region(),
            arena,
            mem::align_of::<u32>(),
        )?;
        if P::AUTHENTICATED {
            self.entry.check_hash(data, hasher)?;
        }

        #[derive(FromBytes)]
        #[repr(C)]
        struct FwVersionHeader {
            image_count: u8,
            rw_count: u8,
            version_len: u8,
            _unused: u8,
            version_addr: u32,
        }
        let (header, rest) =
            LayoutVerified::<_, FwVersionHeader>::new_from_prefix(data).ok_or(
                Error::TooShort {
                    toc_index: self.entry.index(),
                },
            )?;

        if rest.len() < header.version_len as usize {
            return Err(Error::TooShort {
                toc_index: self.entry.index(),
            });
        }
        let (version_str, mut buf) = rest.split_at(header.version_len as usize);

        // Align back to 4-byte boundary.
        buf = buf.get(misalign_of(buf.as_ptr() as usize, 4)..).ok_or(
            Error::TooShort {
                toc_index: self.entry.index(),
            },
        )?;

        let rw_len = mem::size_of::<RwRegion>() * header.rw_count as usize;
        if buf.len() < rw_len {
            return Err(Error::TooShort {
                toc_index: self.entry.index(),
            });
        }
        let (rw_bytes, unparsed_image_regions) = buf.split_at(rw_len);
        // NOTE: This cannot panic, since it checks for alignment (4-byte) and
        // size, which have already been explicitly checked above.
        let rw_regions = LayoutVerified::<_, [RwRegion]>::new_slice(rw_bytes)
            .unwrap()
            .into_slice();

        for rw in rw_regions {
            // NOTE: We only construct a region to check that the start and end
            // addresses are in a valid range.
            let _ = Region::from_start_and_limit(rw.start_addr, rw.end_addr)
                .ok_or(Error::BadRange {
                    toc_index: self.entry.index(),
                })?;
        }

        let image_region_offsets =
            arena.alloc_slice::<u32>(header.image_count as usize)?;
        if header.image_count > 0 {
            // FIXME: we don't need to actually track this "first" offset.
            image_region_offsets[0] = 0;
            for i in 0..header.image_count {
                let rest = &unparsed_image_regions
                    [image_region_offsets[i as usize] as usize..];

                let (img_header, rest) =
                    LayoutVerified::<_, FwRegionHeader>::new_from_prefix(rest)
                        .ok_or(Error::TooShort {
                            toc_index: self.entry.index(),
                        })?;

                let hash_type = match img_header.hash_type {
                    0b00 => hash::Algo::Sha256,
                    0b01 => hash::Algo::Sha384,
                    0b10 => hash::Algo::Sha512,
                    _ => return Err(Error::OutOfRange),
                };
                if rest.len() < hash_type.bytes() {
                    return Err(Error::TooShort {
                        toc_index: self.entry.index(),
                    });
                }
                let (_hash, rest) = rest.split_at(hash_type.bytes());

                let ranges_len = img_header.region_count as usize
                    * mem::size_of::<FwRegionRange>();
                if rest.len() < ranges_len {
                    return Err(Error::TooShort {
                        toc_index: self.entry.index(),
                    });
                }
                let ranges = LayoutVerified::<_, [FwRegionRange]>::new_slice(
                    &rest[..ranges_len],
                )
                .ok_or(Error::TooShort {
                    toc_index: self.entry.index(),
                })?;

                for r in &*ranges {
                    Region::from_start_and_limit(r.start_addr, r.end_addr)
                        .ok_or(Error::BadRange {
                            toc_index: self.entry.index(),
                        })?;
                }

                if i != header.image_count - 1 {
                    image_region_offsets[(i + 1) as usize] =
                        image_region_offsets[i as usize]
                            + ranges_len as u32
                            + hash_type.bytes() as u32
                            + mem::size_of::<FwRegionHeader>() as u32;
                }
            }
        }

        Ok(FwVersion {
            entry: self,
            _data: data,
            version_addr: header.version_addr,
            version_str,
            rw_regions,
            image_region_offsets,
            unparsed_image_regions,
        })
    }
}

/// A "firmware version" element from a PFM.
///
/// To obtain a value of this type, see [`AllowableFw::firmware_versions()`] and
/// [`FwVersionEntry::read()`].
pub struct FwVersion<'a, 'pfm, Flash, Provenance = provenance::Signed> {
    #[allow(unused)]
    entry: FwVersionEntry<'a, 'pfm, Flash, Provenance>,
    _data: &'pfm [u8],
    version_addr: u32,
    version_str: &'pfm [u8],
    rw_regions: &'pfm [RwRegion],
    // TODO: Can we get away with u16 here?
    image_region_offsets: &'pfm [u32],
    unparsed_image_regions: &'pfm [u8],
}

impl<'a, 'pfm, F, P> FwVersion<'a, 'pfm, F, P> {
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pfm, Pfm> {
        self.entry.entry
    }

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
        let hash_type = match header.hash_type {
            0b00 => hash::Algo::Sha256,
            0b01 => hash::Algo::Sha384,
            0b10 => hash::Algo::Sha512,
            _ => unreachable!(),
        };
        let (hash, bytes) = bytes.split_at(hash_type.bytes());
        let ranges =
            LayoutVerified::<_, [FwRegionRange]>::new_slice(bytes).unwrap();
        debug_assert!(ranges.len() == header.region_count as usize);

        Some(FwRegion {
            header: header.into_ref(),
            hash,
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

    /// Returns the raw encoded flags for this element.
    pub fn raw_flags(&self) -> u8 {
        self.flags
    }

    /// Returns the actual flash region described by this region.
    pub fn region(&self) -> Region {
        Region::from_start_and_limit(self.start_addr, self.end_addr)
            .expect("already checked in `read()`")
    }
}

/// An image region within a [`FwVersion`].
///
/// This region is protected by a hash, and only reads to it are permitted.
/// Currently, Manticore only supports SHA-256 hashes here.
pub struct FwRegion<'a> {
    header: &'a FwRegionHeader,
    hash: &'a [u8],
    ranges: &'a [FwRegionRange],
}

#[derive(FromBytes)]
#[repr(C)]
struct FwRegionHeader {
    hash_type: u8,
    region_count: u8,
    flags: u8,
    _reserved: u8,
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

    /// Returns the raw encoded flags for this element.
    pub fn raw_flags(&self) -> u8 {
        self.header.flags
    }

    /// Returns the hash that this region is expected to conform to.
    pub fn image_hash(&self) -> (hash::Algo, &[u8]) {
        let hash_type = match self.header.hash_type {
            0b00 => hash::Algo::Sha256,
            0b01 => hash::Algo::Sha384,
            0b10 => hash::Algo::Sha512,
            _ => unreachable!(),
        };
        (hash_type, self.hash)
    }

    /// Returns the number of flash regions that actually make up this image
    /// region.
    pub fn region_count(&self) -> usize {
        self.header.region_count as usize
    }

    /// Returns the `idx`th flash region in this image region, if there is one.
    pub fn region(&self, idx: usize) -> Option<Region> {
        let range = self.ranges.get(idx)?;
        Some(
            Region::from_start_and_limit(range.start_addr, range.end_addr)
                .expect("already checked in `read()`"),
        )
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

    use serde_json::from_str;
    use testutil::data::keys;

    use crate::crypto::ring;
    use crate::hardware::flash::Ram;
    use crate::io::Write as _;
    use crate::manifest::owned;
    use crate::manifest::testdata;
    use crate::manifest::ManifestExt as _;
    use crate::manifest::ManifestType;
    use crate::manifest::Metadata;
    use crate::mem::BumpArena;
    use crate::mem::OutOfMemory;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn empty() {
        let mut hasher = ring::hash::Engine::new();
        let (mut rsa, mut signer) =
            ring::rsa::from_keypair(keys::KEY1_RSA_KEYPAIR);

        #[rustfmt::skip]
        let pfm: owned::Pfm = from_str(r#"{
            "version_id": 42,
            "elements": []
        }"#).unwrap();
        let bytes = Ram(pfm
            .sign(0x0, hash::Algo::Sha256, &mut hasher, &mut signer)
            .unwrap());

        let container = Container::parse_and_verify(
            &bytes,
            &mut hasher,
            &mut rsa,
            &OutOfMemory,
            &OutOfMemory,
        )
        .unwrap();
        let pfm = ParsedPfm::new(container);

        assert!(pfm
            .platform_id(&mut hasher, &OutOfMemory)
            .unwrap()
            .is_none());
        assert!(pfm
            .flash_device_info(&mut hasher, &OutOfMemory)
            .unwrap()
            .is_none());
        assert_eq!(pfm.allowable_fws().count(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn platform_id() {
        let mut hasher = ring::hash::Engine::new();
        let (mut rsa, mut signer) =
            ring::rsa::from_keypair(keys::KEY1_RSA_KEYPAIR);

        #[rustfmt::skip]
        let pfm: owned::Pfm = from_str(r#"{
            "version_id": 42,
            "elements": [{ "platform_id": "my pfm" }]
        }"#).unwrap();
        let bytes = Ram(pfm
            .sign(0x0, hash::Algo::Sha256, &mut hasher, &mut signer)
            .unwrap());

        let container = Container::parse_and_verify(
            &bytes,
            &mut hasher,
            &mut rsa,
            &OutOfMemory,
            &OutOfMemory,
        )
        .unwrap();
        let pfm = ParsedPfm::new(container);

        let id = pfm.platform_id(&mut hasher, &OutOfMemory).unwrap().unwrap();
        assert_eq!(id.id_string(), b"my pfm");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn fw_versions() {
        let mut hasher = ring::hash::Engine::new();
        let (mut rsa, mut signer) =
            ring::rsa::from_keypair(keys::KEY1_RSA_KEYPAIR);

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
        let bytes = Ram(pfm
            .sign(0x0, hash::Algo::Sha256, &mut hasher, &mut signer)
            .unwrap());

        let container = Container::parse_and_verify(
            &bytes,
            &mut hasher,
            &mut rsa,
            &OutOfMemory,
            &OutOfMemory,
        )
        .unwrap();
        let pfm = ParsedPfm::new(container);

        let device = pfm
            .flash_device_info(&mut hasher, &OutOfMemory)
            .unwrap()
            .unwrap();
        assert_eq!(device.blank_byte(), 0xff);

        let mut allowed_fws = pfm.allowable_fws().map(Some).collect::<Vec<_>>();
        assert_eq!(allowed_fws.len(), 1);

        let allowed = allowed_fws[0]
            .take()
            .unwrap()
            .read(&mut hasher, &OutOfMemory)
            .unwrap();
        assert_eq!(allowed.firmware_id(), b"my cool firmware");

        let mut arena = [0; 256];
        let arena = BumpArena::new(&mut arena);
        let mut versions =
            allowed.firmware_versions().map(Some).collect::<Vec<_>>();
        assert_eq!(allowed_fws.len(), 1);

        let fw = versions[0]
            .take()
            .unwrap()
            .read(&mut hasher, &arena)
            .unwrap();
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

        assert_eq!(imgs[0].image_hash(), (hash::Algo::Sha256, &[42; 32][..]));
        assert_eq!(imgs[0].region_count(), 2);
        assert_eq!(imgs[0].region(0), Some(Region::new(0x10000, 0x1000)));
        assert_eq!(imgs[0].region(1), Some(Region::new(0x18000, 0x800)));
        assert!(imgs[0].region(2).is_none());

        assert_eq!(imgs[1].image_hash(), (hash::Algo::Sha256, &[77; 32][..]));
        assert_eq!(imgs[1].region_count(), 2);
        assert_eq!(imgs[1].region(0), Some(Region::new(0x20000, 0x800)));
        assert_eq!(imgs[1].region(1), Some(Region::new(0x28000, 0x1000)));
        assert!(imgs[1].region(2).is_none());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn baked_pfm1() {
        let mut hasher = ring::hash::Engine::new();
        let (mut rsa, mut signer) =
            ring::rsa::from_keypair(keys::KEY1_RSA_KEYPAIR);
        let mut arena = vec![0; 1024];
        let arena = BumpArena::new(&mut arena);

        let bytes = Ram(testdata::PFM_RSA1);
        // NOTE: Manticore and Cerberus currently have inconsistent signing
        // schemes, so we disable signature verification (for now).
        /*let container = Container::parse_and_verify(
            &bytes,
            &mut hasher,
            &mut rsa,
            &arena,
            &OutOfMemory,
        )
        .unwrap();*/
        let container = Container::parse(&bytes, &arena).unwrap();
        let pfm = ParsedPfm::new(container);

        let device = pfm
            .flash_device_info(&mut hasher, &OutOfMemory)
            .unwrap()
            .unwrap();
        assert_eq!(device.blank_byte(), 0xff);

        let mut allowed_fws = pfm.allowable_fws().map(Some).collect::<Vec<_>>();
        assert_eq!(allowed_fws.len(), 1);

        let allowed = allowed_fws[0]
            .take()
            .unwrap()
            .read(&mut hasher, &OutOfMemory)
            .unwrap();
        assert_eq!(allowed.firmware_id(), b"Firmware");

        let mut arena = [0; 256];
        let arena = BumpArena::new(&mut arena);
        let mut versions =
            allowed.firmware_versions().map(Some).collect::<Vec<_>>();
        assert_eq!(allowed_fws.len(), 1);

        let fw = versions[0]
            .take()
            .unwrap()
            .read(&mut hasher, &arena)
            .unwrap();
        assert_eq!(
            fw.version(),
            (Region::new(0x12345, 7), b"Testing".as_ref())
        );
        assert_eq!(fw.rw_count(), 1);
        assert_eq!(fw.image_count(), 1);

        let rws = fw.rw_regions().collect::<Vec<_>>();
        assert_eq!(rws.len(), 1);
        assert_eq!(rws[0].region(), Region::new(0x200_0000, 0x200_0000));

        let imgs = fw.image_regions().collect::<Vec<_>>();
        assert_eq!(imgs.len(), 1);

        assert_eq!(imgs[0].region_count(), 1);
        assert_eq!(imgs[0].region(0), Some(Region::new(0x0, 0x200_0000)));
        assert!(imgs[0].region(1).is_none());
    }
}
