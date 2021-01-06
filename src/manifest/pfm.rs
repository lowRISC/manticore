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

use crate::crypto::sha256;
use crate::crypto::sha256::Hasher as _;
use crate::hardware::flash::Flash;
use crate::hardware::flash::FlashExt as _;
use crate::hardware::flash::FlashIo;
use crate::io::Read as _;
use crate::manifest::container::Container;
use crate::manifest::provenance;
use crate::manifest::Error;
use crate::mem::Arena;
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

wire_enum! {
    /// A hash type, as defined in certain parts of the PFM.
    ///
    /// Note that we currently only support the SHA-256 variant, even though
    /// Cerberus permits SHA-384 and SHA-512 as well.
    #[allow(missing_docs)]
    pub enum HashType: u8 {
      Sha256 = 0b000,
      // Sha384 = 0b001,
      // Sha512 = 0b010,
    }
}

/// An entry to a PFM's table of contents.
///
/// A TOC entry describes an element in the PFM, such as its format and its
/// location.
///
/// A TOC entry is encoded exactly the same way as this struct is laid
/// out, byte-for-byte.
///
/// See [`Toc`](struct.Toc.html).
#[derive(Copy, Clone, PartialEq, Eq, AsBytes, FromBytes)]
#[repr(C)]
pub struct TocEntry {
    element_type: u8,
    format_version: u8,
    offset: u16,
    len: u16,
    parent_idx: u8,
    hash_idx: u8,
}

#[allow(clippy::len_without_is_empty)]
impl TocEntry {
    /// Returns the type of the element this entry refers to.
    ///
    /// Returns `None` if the encoded element type is not known to Manticore.
    pub fn element_type(&self) -> Option<ElementType> {
        ElementType::from_wire_value(self.element_type)
    }

    /// Returns the format version for the element this entry refers to.
    ///
    /// Along with the type of the element, this value describes how to decode
    /// the serialized element in the PFM.
    pub fn format_version(&self) -> u8 {
        self.format_version
    }

    /// Returns the flash address at which this entry's element begins.
    ///
    /// This value is measured from the start of the PFM's manifest frame,
    /// rather than from the start of the PFM's table of contents.
    pub fn offset(&self) -> usize {
        self.offset as _
    }

    /// Returns the length, in bytes, of this entry's element.
    pub fn len(&self) -> usize {
        self.len as _
    }

    /// Returns the TOC index of this entry's parent, if it has one.
    pub fn parent_idx(&self) -> Option<usize> {
        match self.parent_idx {
            0xff => None,
            x => Some(x as _),
        }
    }

    /// Returns the TOC hash index of this entry, if it has one.
    pub fn hash_idx(&self) -> Option<usize> {
        match self.hash_idx {
            0xff => None,
            x => Some(x as _),
        }
    }
}

/// The table of contents of a PFM.
///
/// The table of contents is encoded as follows:
/// ```text
/// struct Toc {
///   entry_count: u8,
///   hash_count: u8,
///   hash_type: u8,
///   entries: [TocEntry; self.entry_count],
///   hashes: [Digest; self.hash_count],
///   table_hash: Digest,
/// }
/// ```
///
/// The layout of the `TocEntry` type is described in [`TocEntry`]. `Digest` is
/// a hash specified by `hash_type`. Currently, Manticore does not support hash
/// types other than SHA-256. See [`HashType`] for more information.
///
/// The `entries` represent the actual entries to the table of contents; each
/// entry refers to an *element* in the body of the PFM, describing where it is
/// and how to decode it.
///
/// The `hashes` are digests of certain elements, which entries in the table of
/// contents refer to. When an element is read out of flash, its hash is
/// verified against the one present in the TOC, if its TOC entry indicates a
/// hash. This ensures that the element retains protection of the overall
/// manifest signature, even if it is parsed long after the TOC has been read
/// out of flash.
///
/// It is not possible to construct a `Toc` directly; it must be parsed out of
/// a valid [`Pfm`].
///
/// [`TocEntry`]: struct.TocEntry.html
/// [`HashType`]: enum.HashType.html
/// [`Pfm`]: struct.Pfm.html
pub struct Toc<'toc> {
    entries: &'toc [TocEntry],
    hashes: &'toc [sha256::Digest],
}

impl<'toc> Toc<'toc> {
    /// Checks that all invariants of this `Toc` type hold:
    /// - Every pointer to a hash is in-bounds.
    /// - Every pointer to a parent is in-bounds.
    ///
    /// Returns true if the invariants are upheld.
    fn verify_invariants(&self) -> bool {
        for entry in self.entries {
            if let Some(idx) = entry.hash_idx() {
                if self.hashes.len() <= idx {
                    return false;
                }
            }
            if let Some(idx) = entry.parent_idx() {
                if self.entries.len() <= idx {
                    return false;
                }
            }
        }

        true
    }

    /// Returns the number of entries in this `Toc`.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether this `Toc` is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the `i`th entry in this `Toc`.
    ///
    /// If there is not `i`th entry, `None` is returned. If the entry specifies
    /// a hash, it is also returned, otherwise `Some((Some(_), None))` is
    /// returned.
    pub fn entry(
        &self,
        i: usize,
    ) -> Option<(&'toc TocEntry, Option<&'toc sha256::Digest>)> {
        let entry = self.entries.get(i)?;
        match entry.hash_idx() {
            // NOTE: This indexing operation cannot panic due to `Toc`'s invariants.
            Some(idx) => Some((entry, Some(&self.hashes[idx]))),
            None => Some((entry, None)),
        }
    }

    /// Returns an iterator over this `Toc`'s entries and their associated
    /// hashes, if they specify one.
    pub fn entries(
        &self,
    ) -> impl Iterator<Item = (&'toc TocEntry, Option<&'toc sha256::Digest>)> + '_
    {
        // NOTE: The unwrap() below cannot panic, because `i` is always in-bounds.
        (0..self.entries.len()).map(move |i| self.entry(i).unwrap())
    }

    /// Returns an iterator over this `Toc`'s entries of a specific type.
    ///
    /// The items returned by this iterator also include the index of the entry
    /// in the overall table.
    pub fn entries_of_type(
        &self,
        ty: ElementType,
    ) -> impl Iterator<
        Item = (usize, &'toc TocEntry, Option<&'toc sha256::Digest>),
    > + '_ {
        self.entries()
            .enumerate()
            .map(|(i, (e, h))| (i, e, h))
            .filter(move |(_, e, _)| e.element_type() == Some(ty))
    }

    /// Returns the first entry in this `Toc` of a particular type, if any.
    pub fn first_entry_of_type(
        &self,
        ty: ElementType,
    ) -> Option<(usize, &'toc TocEntry, Option<&'toc sha256::Digest>)> {
        self.entries_of_type(ty).next()
    }

    /// Returns an iterator over all `Toc` entries that have the given parent
    /// index.
    ///
    /// The items returned by this iterator also include the index of the entry
    /// in the overall table.
    pub fn children_of(
        &self,
        parent_idx: usize,
    ) -> impl Iterator<
        Item = (usize, &'toc TocEntry, Option<&'toc sha256::Digest>),
    > + '_ {
        self.entries()
            .enumerate()
            .map(|(i, (e, h))| (i, e, h))
            .filter(move |(_, e, _)| e.parent_idx() == Some(parent_idx))
    }
}

/// A Platform Firmware Manifest.
///
/// This type provides functions for parsing a PFM's table of contents and
/// using it to extract other portions of the PFM.
///
/// This type only maintains the TOC in memory for book-keeping.
pub struct Pfm<'pfm, Flash> {
    toc: Toc<'pfm>,
    flash: &'pfm Flash,
}

impl<'pfm, F: Flash> Pfm<'pfm, F> {
    /// Parses the table of contents of a PFM.
    ///
    /// This function may allocate on `toc_arena`, even if parsing fails; in
    /// that case, it is the caller's responsibility to reset the arena.
    pub fn parse<'flash: 'pfm, 'arena: 'pfm>(
        container: &'flash Container<F, provenance::Signed>,
        sha: &impl sha256::Builder,
        toc_arena: &'arena impl Arena,
    ) -> Result<Self, Error> {
        let flash = container.flash();
        let mut io = FlashIo::new(flash)?;
        io.skip_bytes(container.body().offset as usize);

        let entry_count = io.read_le::<u8>()?;
        let hash_count = io.read_le::<u8>()?;
        let hash_type = io.read_le::<u8>()?;
        // FIXME: we don't deal with hash types that aren't SHA-256.
        if hash_type != HashType::Sha256.to_wire_value() {
            return Err(Error::OutOfRange);
        }
        let reserved = io.read_le::<u8>()?;

        let mut cursor = io.cursor();
        let entries = flash.read_slice::<TocEntry>(
            cursor,
            entry_count as usize,
            toc_arena,
        )?;
        cursor += mem::size_of_val(entries) as u32;

        let hashes = flash.read_slice::<sha256::Digest>(
            cursor,
            hash_count as usize,
            toc_arena,
        )?;
        cursor += mem::size_of_val(hashes) as u32;

        let mut toc_hash = [0; 32];
        flash.read(cursor, &mut toc_hash)?;

        let mut hasher = sha.new_hasher()?;

        hasher.write(&[entry_count])?;
        hasher.write(&[hash_count])?;
        hasher.write(&[hash_type])?;
        hasher.write(&[reserved])?;

        hasher.write(entries.as_bytes())?;
        hasher.write(hashes.as_bytes())?;

        let mut hash = [0; 32];
        hasher.finish(&mut hash)?;
        if hash != toc_hash {
            return Err(Error::SignatureFailure);
        }

        let toc = Toc { entries, hashes };
        if !toc.verify_invariants() {
            return Err(Error::OutOfRange);
        }

        Ok(Pfm { toc, flash })
    }

    /// Returns this PFM's table of contents.
    pub fn toc(&self) -> &Toc<'pfm> {
        &self.toc
    }

    /// Extracts the Platform ID from this PFM, allocating it onto the provided
    /// arena. Returns `None` if the Platform ID is missing.
    ///
    /// This function will also verify the hash of the Platform ID, if one is
    /// present.
    pub fn platform_id<'id>(
        &self,
        sha: &impl sha256::Builder,
        arena: &'id impl Arena,
    ) -> Result<Option<&'id [u8]>, Error>
    where
        'pfm: 'id,
    {
        let (_, entry, hash) =
            match self.toc.first_entry_of_type(ElementType::PlatformId) {
                Some(x) => x,
                None => return Ok(None),
            };
        let start = entry.offset() as u32;
        if entry.len() < 4 {
            return Err(Error::OutOfRange);
        }

        let mut header = [0; 4];
        self.flash.read(start, &mut header)?;
        let len = header[0];
        let max_len = entry.len() - 4;
        if len as usize >= max_len {
            return Err(Error::OutOfRange);
        }
        let align_len = max_len - len as usize;
        if align_len >= 4 {
            return Err(Error::OutOfRange);
        }

        let id = self
            .flash
            .read_slice::<u8>(start + 4, len as usize, arena)?;

        if let Some(expected) = hash {
            let mut hasher = sha.new_hasher()?;
            hasher.write(&header)?;
            hasher.write(id)?;

            // Trailing bytes after the id; these need to be included in the hash.
            let mut align = [0; 4];
            let align = &mut align[..align_len as usize];
            self.flash.read(start + 4 + len as u32, align)?;
            hasher.write(&*align)?;

            let mut hash = [0; 32];
            hasher.finish(&mut hash)?;
            if &hash != expected {
                return Err(Error::SignatureFailure);
            }
        }

        Ok(Some(id))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::crypto::ring::sha256::Builder as RingSha;
    use crate::crypto::sha256::Builder as _;
    use crate::hardware::flash::Ram;
    use crate::io::Write as _;
    use crate::manifest::container::test::make_rsa_engine;
    use crate::manifest::container::Container;
    use crate::manifest::container::Containerizer;
    use crate::manifest::container::Metadata;
    use crate::manifest::ManifestType;
    use crate::mem::OutOfMemory;

    #[test]
    fn smoke() {
        // This is a basic test to ensure that parsing a PFM and pulling out the
        // platform id works at all.

        const TOC_BASE: &[u8] = &[
            0x01, 0x01, 0x00,
            0x00, // Entry #, hash #, hash type (sha256), reserved.
            0x03, 0x01, 0x58, 0x00, // Type 3, version 1, offset 88.
            0x0c, 0x00, 0xff, 0x00, // Length 12, no parent, hash idx 0.
        ];

        const ID_ELEMENT: &[u8] = &[
            0x06, 0x00, 0x00, 0x00, // 6 bytes.
            b'm', b'y', b' ', b'p', // Message: "my pfm".
            b'f', b'm', 0x11, 0x11, // 2 bytes padding!
        ];

        let sha = RingSha::new();
        let mut hash = [0; 32];

        let mut pfm_vec = Vec::new();
        pfm_vec.extend_from_slice(TOC_BASE);

        // Add the element hash.
        sha.hash_contiguous(&ID_ELEMENT, &mut hash).unwrap();
        pfm_vec.extend_from_slice(&hash);

        // Add the TOC hash.
        sha.hash_contiguous(&pfm_vec, &mut hash).unwrap();
        pfm_vec.extend_from_slice(&hash);

        // Add the element itself.
        pfm_vec.extend_from_slice(ID_ELEMENT);

        let (mut rsa, mut signer) = make_rsa_engine();
        let mut pfm_bytes = [0; 1024];
        let mut builder = Containerizer::new(&mut pfm_bytes)
            .unwrap()
            .with_type(ManifestType::Pfm)
            .unwrap()
            .with_metadata(&Metadata { version_id: 42 })
            .unwrap();
        builder.write_bytes(&pfm_vec).unwrap();
        let pfm_bytes = builder.sign(&sha, &mut signer).unwrap();

        let manifest = Container::parse_and_verify(
            Ram(pfm_bytes),
            &sha,
            &mut rsa,
            &OutOfMemory,
        )
        .unwrap();

        let pfm = Pfm::parse(&manifest, &sha, &OutOfMemory).unwrap();
        let id = pfm.platform_id(&sha, &OutOfMemory).unwrap().unwrap();
        assert_eq!(id, b"my pfm");
    }
}
