// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cerberus manifest containers.
//!
//! See the `manticore::manifest` documentation for more information.

use core::marker::PhantomData;
use core::mem;

use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::crypto::hash;
use crate::crypto::hash::EngineExt as _;
use crate::crypto::sig;
use crate::hardware::flash::Flash;
use crate::hardware::flash::FlashExt as _;
use crate::hardware::flash::FlashIo;
use crate::hardware::flash::Region;
use crate::io::Read as _;
use crate::manifest::provenance;
use crate::manifest::Error;
use crate::manifest::Manifest;
use crate::manifest::ManifestType;
use crate::manifest::ElementsOf;
use crate::mem::Arena;
use crate::protocol::wire::WireEnum;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Metadata for a [`Container`].
///
/// This struct describes metadata attached to every manifest, which makes up
/// part of the signed component.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Metadata {
    /// The "version" or "manifest ID", a monotonically increasing integer that
    /// Manticore can use to protect against playback attacks, by refusing to
    /// load a manifest with a smaller version number.
    ///
    /// When minting a new manifest, a signing authority should make sure to
    /// bump this value.
    pub version_id: u32,
}

/// A TOC entry's raw bits.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug, AsBytes, FromBytes)]
#[repr(C)]
pub(crate) struct RawTocEntry {
    pub element_type: u8,
    pub parent_type: u8,
    pub format_version: u8,
    pub hash_idx: u8,
    pub offset: u16,
    pub len: u16,
}

/// An entry to a manifest's table of contents.
///
/// A TOC entry describes an element in manifest, such as its format and its
/// location.
///
/// A TOC entry is encoded exactly the same way as this struct is laid
/// out, byte-for-byte.
///
/// See [`Toc`](struct.Toc.html).
pub struct TocEntry<'entry, 'toc, M> {
    toc: &'entry Toc<'toc, M>,
    // Invariant: index is always a valid index into `toc.entries`.
    index: usize,
}

impl<'entry, 'toc, M: Manifest> TocEntry<'entry, 'toc, M> {
    #[inline]
    fn raw(self) -> &'toc RawTocEntry {
        &self.toc.entries[self.index]
    }

    /// Returns this entry's index in the TOC.
    pub fn index(self) -> usize {
        self.index
    }

    /// Returns the type of the element this entry refers to.
    pub fn element_type(self) -> Option<ElementsOf<M>> {
        <ElementsOf<M> as WireEnum>::from_wire_value(self.raw().element_type)
    }

    /// Returns the format version of this TOC entry.
    ///
    /// Note that this is always a version Manticore supports;
    /// Manticore will refuse to parse TOCs with versions it does not
    /// support.
    pub fn format_version(self) -> u8 {
        self.raw().format_version
    }

    /// Returns a flash region indicating where this entry's data is located.
    pub fn region(self) -> Region {
        Region::new(self.raw().offset as u32, self.raw().len as u32)
    }

    /// Returns this entry's parent, if it has one.
    pub fn parent(self) -> Option<Self> {
        match self.raw().parent_type {
            0xff => None,
            parent_type => {
                for i in (0..self.index()).rev() {
                    let e = self.toc.entry(i).expect("obviously in range");
                    if e.raw().element_type == parent_type {
                        return Some(e);
                    }
                }
                unreachable!("previously verified by check_invariants()")
            }
        }
    }

    /// Returns this entry's hash, if it has one.
    pub fn hash(self) -> Option<&'entry [u8]> {
        match self.raw().hash_idx {
            0xff => None,
            x => self.toc.hash(x as usize),
        }
    }

    /// Helper for checking that the hash specified in this entry matches the data
    /// provided.
    pub(crate) fn check_hash(
        self,
        data: &[u8],
        hasher: &mut impl hash::Engine,
    ) -> Result<(), Error> {
        let expected = match self.hash() {
            Some(h) => h,
            None => return Ok(()),
        };

        let mut hasher = hasher.new_hash(self.toc.hash_type)?;
        hasher.write(data)?;
        hasher
            .expect(expected)
            .map_err(|error| Error::BadElementHash {
                error,
                toc_index: self.index(),
            })
    }

    /// Returns an iterator over all of this entry's children.
    pub fn children(self) -> impl Iterator<Item = TocEntry<'entry, 'toc, M>> {
        let mut index = self.index() + 1;
        core::iter::from_fn(move || loop {
            let entry = self.toc.entry(index)?;
            if entry.raw().element_type == self.raw().element_type {
                // We've seen another element of the same type, so there's no
                // children with this element type that can follow.
                return None;
            }

            index += 1;
            if entry.raw().parent_type == self.raw().element_type {
                return Some(entry);
            }
        })
    }
    /// Returns an iterator over all of this entry's children of a specific
    /// type.
    pub fn children_of(self, ty: ElementsOf<M>) -> impl Iterator<Item = TocEntry<'entry, 'toc, M>> where
    ElementsOf<M>: PartialEq, {
        self.children().filter(move |e| e.element_type() == Some(ty))
    }

}

// NOTE: Implemented manually, since derive() would generate incorrect bounds
// M: Clone and M: Copy on the impls.
impl<M> Clone for TocEntry<'_, '_, M> {
    fn clone(&self) -> Self {
        TocEntry {
            toc: self.toc,
            index: self.index,
        }
    }
}

impl<M> Copy for TocEntry<'_, '_, M> {}

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
/// The layout of the `TocEntry` type is described in [`TocEntry`].
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
/// a valid [`Manifest`].
pub struct Toc<'toc, M> {
    entries: &'toc [RawTocEntry],
    // How this is interpreted is dependent on `hash_type`.
    hashes: &'toc [u8],
    hash_type: hash::Algo,
    _ph: PhantomData<fn() -> M>,
}

impl<'toc, M: Manifest> Toc<'toc, M> {
    /// Checks that all invariants of this `Toc` type hold:
    /// - Every pointer to a hash is in-bounds.
    /// - Every pointer to a parent is in-bounds.
    /// - Every type/version pair is well-known.
    ///
    /// Returns true if the invariants are upheld.
    fn check_invariants(&self) -> Result<(), Error> {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.hash_idx != 0xff
                && self.hash(entry.hash_idx as usize).is_none()
            {
                return Err(Error::BadHashIndex { toc_index: i });
            }

            // NOTE: Unfortunately, this check is necessarilly quadratic
            // in the TOC size.
            if entry.parent_type != 0xff {
                let mut has_parent = false;
                for e in &self.entries[..i] {
                    if e.element_type == entry.parent_type {
                        has_parent = true;
                        break;
                    }
                }
                if !has_parent {
                    return Err(Error::BadParent { toc_index: i });
                }
            }
        }

        Ok(())
    }

    /// Returns the number of entries in this `Toc`.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether this `Toc` is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the hash algorithm used in this `Toc`'s hashes.
    pub fn hash_type(&self) -> hash::Algo {
        self.hash_type
    }

    /// Returns the `i`th hash.
    fn hash(&self, i: usize) -> Option<&[u8]> {
        let start = i.checked_mul(self.hash_type.bytes())?;
        let end = start.checked_add(self.hash_type.bytes())?;
        self.hashes.get(start..end)
    }

    /// Returns the `i`th entry in this `Toc`.
    ///
    /// If there is not `i`th entry, `None` is returned. If the entry specifies
    /// a hash, it is also returned, otherwise `Some((Some(_), None))` is
    /// returned.
    pub fn entry(&self, i: usize) -> Option<TocEntry<'_, 'toc, M>> {
        if i >= self.len() {
            return None;
        }

        Some(TocEntry {
            toc: self,
            index: i,
        })
    }

    /// Returns an iterator over this `Toc`'s entries and their associated
    /// hashes, if they specify one.
    pub fn entries(&self) -> impl Iterator<Item = TocEntry<'_, 'toc, M>> + '_ {
        (0..self.entries.len()).map(move |i| TocEntry {
            toc: self,
            index: i,
        })
    }

    /// Returns an iterator over this `Toc`'s entries of a specific type.
    pub fn entries_of(&self, ty: ElementsOf<M>) -> impl Iterator<Item = TocEntry<'_, 'toc, M>> + '_
        where ElementsOf<M>: PartialEq,
    {
        self.entries().filter(move |e| e.element_type() == Some(ty))
    }

    /// Returns the first element of the given type in this `Toc`.
    ///
    /// This function should be used to discover "singleton" entries, entries
    /// such that only the very first appearance thereof in a TOC is used, with
    /// the rest ignored.
    pub fn singleton(&self, ty: ElementsOf<M>) -> Option<TocEntry<'_, 'toc, M>>
    where ElementsOf<M>: PartialEq,
    {
        self.entries_of(ty).next()
    }
}

/// A `Container`'s raw header bits.
///
/// This struct includes the TOC header as well.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug, AsBytes, FromBytes)]
#[repr(C)]
pub(crate) struct RawHeader {
    pub total_len: u16,
    pub manifest_type: u16,
    pub version_id: u32,
    pub sig_len: u16,
    pub sig_ty: u8,
    pub reserved1: u8,

    pub entry_count: u8,
    pub hash_count: u8,
    pub hash_type: u8,
    pub reserved2: u8,
}

/// A parsed, verified, manifest container.
///
/// This type represents a generic, authenticated manifest. A value of this
/// type is a witness that authentication via signature was successful; it is
/// not possible to parse a `Container` without also verifying it.
///
/// See the [module documentation](index.html) for more information.
pub struct Container<'f, M, F, Provenance = provenance::Signed> {
    header: &'f RawHeader,
    flash: &'f F,
    toc: Toc<'f, M>,
    _ph: PhantomData<Provenance>,
}

impl<'f, M: Manifest, F: Flash> Container<'f, M, F, provenance::Signed> {
    /// Parses and verifies a `Container` using the provided cryptographic
    /// primitives.
    ///
    /// This is the only function capable of prodiucing a container with the
    /// `Signed` provenance.
    ///
    /// `buf` must be aligned to a four-byte boundary.
    pub fn parse_and_verify(
        flash: &'f F,
        hasher: &mut impl hash::Engine,
        sig_verify: &mut impl sig::Verify,
        toc_arena: &'f impl Arena,
        verify_arena: &impl Arena,
    ) -> Result<Self, Error> {
        let c = Self::parse_inner(flash, toc_arena)?;

        c.verify_toc_hash(hasher, verify_arena)?;
        c.verify_signature(hasher, sig_verify, verify_arena)?;

        Ok(c)
    }
}

impl<'f, M: Manifest, F: Flash> Container<'f, M, F, provenance::Adhoc> {
    /// Parses a `Container` without verifying the signature.
    ///
    /// The value returned by this function cannot be used for trusted
    /// operations. See [`Container::parse_and_verify()`].
    #[inline]
    pub fn parse(
        flash: &'f F,
        toc_arena: &'f impl Arena,
    ) -> Result<Self, Error> {
        Self::parse_inner(flash, toc_arena)
    }
}

impl<'f, M: Manifest, F: Flash, Provenance> Container<'f, M, F, Provenance> {
    /// Downgrades this `Container`'s provenance to `Adhoc`, forgetting that
    /// this container might have had a valid signature.
    #[inline(always)]
    pub fn downgrade(self) -> Container<'f, M, F, provenance::Adhoc> {
        Container {
            header: self.header,
            flash: self.flash,
            toc: self.toc,
            _ph: PhantomData,
        }
    }

    /// Verifies the TOC hash for this `Container`.
    pub(crate) fn verify_toc_hash(
        &self,
        hasher: &mut impl hash::Engine,
        verify_arena: &impl Arena,
    ) -> Result<(), Error> {
        let expected_hash_offset = mem::size_of::<RawHeader>()
            + mem::size_of_val(self.toc().entries)
            + mem::size_of_val(self.toc().hashes);
        let expected_toc_hash = self.flash.read_slice::<u8>(
            expected_hash_offset as u32,
            self.toc().hash_type.bytes(),
            verify_arena,
        )?;

        if !hasher.supports(self.toc.hash_type) {
            return Err(Error::UnsupportedHashType(self.toc.hash_type));
        }

        let mut toc_hasher = hasher.new_hash(self.toc.hash_type)?;
        let toc_header = &self.header.as_bytes()[12..];
        toc_hasher.write(toc_header)?;
        toc_hasher.write(self.toc().entries.as_bytes())?;
        toc_hasher.write(self.toc().hashes)?;

        toc_hasher
            .expect(expected_toc_hash)
            .map_err(Error::BadTocHash)
    }

    /// Verifies the signature for this `Container`.
    pub(crate) fn verify_signature(
        &self,
        hasher: &mut impl hash::Engine,
        sig_verify: &mut impl sig::Verify,
        verify_arena: &impl Arena,
    ) -> Result<(), Error> {
        let mut bytes = [0u8; 16];
        let signed_region = self.signed_region();
        let mut r = FlashIo::new(&self.flash)?;
        r.reslice(signed_region);

        // Currently hard-coded to SHA-256, but this is not the correct way
        // to verify the signature; the signature is not a hash of hashes as
        // specified, but we do not have a way to do this with our current
        // APIs.
        let mut hasher = hasher.new_hash(hash::Algo::Sha256)?;
        while r.remaining_data() > 0 {
            let to_read = r.remaining_data().min(16);
            r.read_bytes(&mut bytes[..to_read])?;
            hasher.write(&bytes[..to_read])?;
        }

        let mut digest = [0; 32];
        hasher.finish(&mut digest)?;

        let sig =
            self.flash
                .read_direct(self.signature_region(), verify_arena, 1)?;
        sig_verify.verify(&[&digest], sig)?;
        Ok(())
    }

    /// Performs a parse without verifying the signature, returning the
    /// the necessary arguments to pass to `verify_signature()`, if that were
    /// necessary.
    fn parse_inner(
        flash: &'f F,
        toc_arena: &'f impl Arena,
    ) -> Result<Self, Error> {
        // TODO(#58): Manticore currently ignores header.sig_type.
        let header = flash.read_object::<RawHeader>(0, toc_arena)?;

        if ManifestType::from_wire_value(header.manifest_type) != Some(M::TYPE)
        {
            return Err(Error::BadMagic(header.manifest_type));
        }

        if header.sig_len > header.total_len {
            return Err(Error::OutOfRange);
        }

        let hash_type = match header.hash_type {
            0b00 => hash::Algo::Sha256,
            0b01 => hash::Algo::Sha384,
            0b10 => hash::Algo::Sha512,
            _ => return Err(Error::OutOfRange),
        };

        // Unused values are currently required to be zeroed by the spec.
        if header.reserved1 != 0 || header.reserved2 != 0 {
            return Err(Error::OutOfRange);
        }

        let mut cursor = mem::size_of::<RawHeader>() as u32;
        let entries = flash.read_slice::<RawTocEntry>(
            cursor,
            header.entry_count as usize,
            toc_arena,
        )?;
        cursor += mem::size_of_val(entries) as u32;

        let hashes = flash.read_slice::<u8>(
            cursor,
            header.hash_count as usize * hash_type.bytes(),
            toc_arena,
        )?;

        let toc = Toc {
            entries,
            hashes,
            hash_type,
            _ph: PhantomData,
        };
        toc.check_invariants()?;

        Ok(Self {
            header,
            flash,
            toc,
            _ph: PhantomData,
        })
    }

    /// Returns the [`ManifestType`] for this `Container`.
    pub fn manifest_type(&self) -> ManifestType {
        ManifestType::from_wire_value(self.header.manifest_type)
            .expect("verified in parse_inner()")
    }

    /// Checks whether this `Container` can replace `other`.
    ///
    /// In other words, `self` must:
    /// - Be of the same type as `other`.
    /// - Have a greater or equal `id` number than `other`.
    pub fn can_replace(&self, other: &Self) -> bool {
        self.header.manifest_type == other.header.manifest_type
            && self.header.version_id >= other.header.version_id
    }

    /// Returns this `Container`'s [`Metadata`] value.
    pub fn metadata(&self) -> Metadata {
        Metadata {
            version_id: self.header.version_id,
        }
    }

    /// Returns this `Container`'s [`Toc`].
    pub fn toc(&self) -> &Toc<'f, M> {
        &self.toc
    }

    /// Returns the backing storage for this `Container`.
    pub fn flash(&self) -> &'f F {
        self.flash
    }

    /// Returns the region of flash containing the signed bytes of this
    /// `Container`.
    pub fn signed_region(&self) -> Region {
        Region::new(0, (self.header.total_len - self.header.sig_len) as u32)
    }

    /// Returns the region of flash containing this `Container`'s signature.
    pub fn signature_region(&self) -> Region {
        let signed = self.signed_region();
        Region::new(signed.len, self.header.sig_len as u32)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    use serde_json::from_str;
    use testutil::data::keys;

    use crate::crypto::ring;
    use crate::hardware::flash::Ram;
    use crate::manifest;
    use crate::manifest::owned;
    use crate::manifest::pfm;
    use crate::manifest::pfm::Pfm;
    use crate::mem::OutOfMemory;

    // NOTE: To effectively run these tests, we use PFM-from-JSON to generate
    // some of the tests, but they're intended to be independent of the actual
    // manifest type.

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
        type Flash = Ram<Vec<u8>>;

        let container: Container<'_, Pfm, Flash> = Container::parse_and_verify(
            &bytes,
            &mut hasher,
            &mut rsa,
            &OutOfMemory,
            &OutOfMemory,
        )
        .unwrap();
        assert_eq!(container.metadata().version_id, 42);

        let toc = container.toc();
        assert_eq!(toc.len(), 0);
        assert!(toc.is_empty());
        assert!(toc.entry(0).is_none());
        assert_eq!(toc.entries().count(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn one_element() {
        let mut hasher = ring::hash::Engine::new();
        let (mut rsa, mut signer) =
            ring::rsa::from_keypair(keys::KEY1_RSA_KEYPAIR);

        #[rustfmt::skip]
        let pfm: owned::Pfm = from_str(r#"{
            "version_id": 42,
            "elements": [{ "platform_id": "blah" }]
        }"#).unwrap();
        let bytes = Ram(pfm
            .sign(0x0, hash::Algo::Sha256, &mut hasher, &mut signer)
            .unwrap());
        type Flash = Ram<Vec<u8>>;

        let container: Container<'_, Pfm, Flash> = Container::parse_and_verify(
            &bytes,
            &mut hasher,
            &mut rsa,
            &OutOfMemory,
            &OutOfMemory,
        )
        .unwrap();

        let toc = container.toc();
        assert_eq!(toc.len(), 1);
        assert_eq!(
            toc.entries().map(TocEntry::index).collect::<Vec<_>>(),
            vec![0]
        );

        let first = toc.entry(0).unwrap();
        assert_eq!(first.index(), 0);
        assert_eq!(first.element_type().unwrap(), manifest::ElementType::PlatformId);
        assert!(first.parent().is_none());
        assert!(first.hash().is_some());
        assert_eq!(first.children().count(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn with_child() {
        let mut hasher = ring::hash::Engine::new();
        let (mut rsa, mut signer) =
            ring::rsa::from_keypair(keys::KEY1_RSA_KEYPAIR);

        #[rustfmt::skip]
        let pfm: owned::Pfm = from_str(r#"{
            "version_id": 42,
            "elements": [{
                "platform_id": "blah",
                "children": [{
                    "blank_byte": "0x55",
                    "hashed": false
                }]
            }]
        }"#).unwrap();
        let bytes = Ram(pfm
            .sign(0x0, hash::Algo::Sha256, &mut hasher, &mut signer)
            .unwrap());
        type Flash = Ram<Vec<u8>>;

        let container: Container<'_, Pfm, Flash> = Container::parse_and_verify(
            &bytes,
            &mut hasher,
            &mut rsa,
            &OutOfMemory,
            &OutOfMemory,
        )
        .unwrap();

        let toc = container.toc();
        assert_eq!(toc.len(), 2);
        assert_eq!(
            toc.entries().map(TocEntry::index).collect::<Vec<_>>(),
            vec![0, 1]
        );

        let first = toc.entry(0).unwrap();
        assert_eq!(first.index(), 0);
        assert_eq!(first.element_type().unwrap(), manifest::ElementType::PlatformId);
        assert!(first.parent().is_none());
        assert!(first.hash().is_some());

        let children = first.children().collect::<Vec<_>>();
        assert_eq!(children.len(), 1);
        let second = children[0];
        assert_eq!(second.index(), 1);
        assert_eq!(
            second.element_type().unwrap(),
            manifest::ElementType::Specific(pfm::ElementType::FlashDevice),
        );
        assert_eq!(second.parent().unwrap().index(), 0);
        assert!(second.hash().is_none());
    }
}
