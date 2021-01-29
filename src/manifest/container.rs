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

use crate::crypto::rsa;
use crate::crypto::sha256;
use crate::crypto::sha256::Hasher as _;
use crate::hardware::flash::Flash;
use crate::hardware::flash::FlashExt as _;
use crate::hardware::flash::FlashIo;
use crate::hardware::flash::Region;
use crate::io::Read as _;
use crate::manifest::provenance;
use crate::manifest::Error;
use crate::manifest::Manifest;
use crate::manifest::ManifestType;
use crate::mem::Arena;
use crate::protocol::wire::WireEnum;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Metadata for a [`Container`].
///
/// This struct describes metadata attached to every manifest, which makes up
/// part of the signed component.
///
/// [`Comtainer`]: struct.Container.html
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

wire_enum! {
    /// A hash type for a manifest [`Toc`]
    ///
    /// Note that we currently only support the SHA-256 variant, even though
    /// Cerberus permits SHA-384 and SHA-512 as well.
    ///
    /// [`Toc`]: struct.Toc.html
    #[allow(missing_docs)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum HashType: u8 {
      Sha256 = 0b000,
      // Sha384 = 0b001,
      // Sha512 = 0b010,
    }
}

/// A TOC entry's raw bits.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug, AsBytes, FromBytes)]
#[repr(C)]
pub(crate) struct RawTocEntry {
    pub element_type: u8,
    pub format_version: u8,
    pub offset: u16,
    pub len: u16,
    pub parent_idx: u8,
    pub hash_idx: u8,
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
    pub fn element_type(self) -> M::ElementType {
        <M::ElementType as WireEnum>::from_wire_value(self.raw().element_type)
            .expect("previously verified by check_invariants()")
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
        match self.raw().parent_idx {
            0xff => None,
            x => Some(
                self.toc
                    .entry(x as usize)
                    .expect("previously verified by check_invariants()"),
            ),
        }
    }

    /// Returns this entry's hash, if it has one.
    pub fn hash(self) -> Option<&'toc sha256::Digest> {
        match self.raw().hash_idx {
            0xff => None,
            x => Some(&self.toc.hashes[x as usize]),
        }
    }

    /// Returns an iterator over all of this entry's children.
    pub fn children(self) -> impl Iterator<Item = TocEntry<'entry, 'toc, M>> {
        self.toc
            .entries()
            .filter(move |e| self.index == e.raw().parent_idx as usize)
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
pub struct Toc<'toc, M> {
    entries: &'toc [RawTocEntry],
    hashes: &'toc [sha256::Digest],
    _ph: PhantomData<fn() -> M>,
}

impl<'toc, M: Manifest> Toc<'toc, M> {
    /// Checks that all invariants of this `Toc` type hold:
    /// - Every pointer to a hash is in-bounds.
    /// - Every pointer to a parent is in-bounds.
    /// - Every type/version pair is well-known.
    ///
    /// Returns true if the invariants are upheld.
    fn check_invariants(&self) -> bool {
        for entry in self.entries {
            match <M::ElementType as WireEnum>::from_wire_value(
                entry.element_type,
            ) {
                Some(e) => {
                    if entry.format_version < M::min_version(e) {
                        return false;
                    }
                }
                None => return false,
            }

            if entry.hash_idx != 0xff
                && self.hashes.len() <= entry.hash_idx as usize
            {
                return false;
            }

            if entry.parent_idx != 0xff
                && self.hashes.len() <= entry.parent_idx as usize
            {
                return false;
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
}

/// A parsed, verified, manifest container.
///
/// This type represents a generic, authenticated manifest. A value of this
/// type is a witness that authentication via signature was successful; it is
/// not possible to parse a `Container` without also verifying it.
///
/// See the [module documentation](index.html) for more information.
pub struct Container<'f, M, F, Provenance = provenance::Signed> {
    manifest_type: ManifestType,
    metadata: Metadata,
    flash: &'f F,
    toc: Toc<'f, M>,
    _ph: PhantomData<Provenance>,
}

/// The length of the container header in bytes:
/// two halves, a word, another half, and two bytes of padding.
const HEADER_LEN: usize = 2 + 2 + 4 + 2 + 2;

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
        sha: &impl sha256::Builder,
        rsa: &mut impl rsa::Engine,
        toc_arena: &'f impl Arena,
        verify_arena: &impl Arena,
    ) -> Result<Self, Error> {
        let (mut c, sig, signed) = Self::parse_inner(flash, sha, toc_arena)?;

        let mut bytes = [0u8; 16];
        let mut r = FlashIo::new(&mut c.flash)?;
        r.reslice(signed);

        let mut hasher = sha.new_hasher()?;
        while r.remaining_data() > 0 {
            let to_read = r.remaining_data().min(16);
            r.read_bytes(&mut bytes[..to_read])?;
            hasher.write(&bytes[..to_read])?;
        }

        let mut digest = [0; 32];
        hasher.finish(&mut digest)?;

        let sig = c.flash.read_direct(sig, verify_arena, 1)?;
        rsa.verify_signature(sig, &digest)?;

        Ok(c)
    }
}

impl<'f, M: Manifest, F: Flash> Container<'f, M, F, provenance::Adhoc> {
    /// Parses a `Container` without verifying the signature.
    ///
    /// The value returned by this function cannot be used for trusted
    /// operations. See [`parse_and_verify()`].
    ///
    /// [`parse_and_verify()`]: struct.Container.html#method.parse_and_verify
    #[inline]
    pub fn parse(
        flash: &'f F,
        sha: &impl sha256::Builder,
        toc_arena: &'f impl Arena,
    ) -> Result<Self, Error> {
        let (c, _, _) = Self::parse_inner(flash, sha, toc_arena)?;
        Ok(c)
    }
}

impl<'f, M: Manifest, F: Flash, Provenance> Container<'f, M, F, Provenance> {
    /// Downgrades this `Container`'s provenance to `Adhoc`, forgetting that
    /// this container might have had a valid signature.
    #[inline(always)]
    pub fn downgrade(self) -> Container<'f, M, F, provenance::Adhoc> {
        Container {
            manifest_type: self.manifest_type,
            metadata: self.metadata,
            flash: self.flash,
            toc: self.toc,
            _ph: PhantomData,
        }
    }

    /// Performs a parse without verifying the signature, returning the
    /// the necessary arguments to pass to `verify_signature()`, if that were
    /// necessary.
    fn parse_inner(
        mut flash: &'f F,
        sha: &impl sha256::Builder,
        toc_arena: &'f impl Arena,
    ) -> Result<(Self, Region, Region), Error> {
        let flash_len = flash.size()? as usize;

        if HEADER_LEN > flash_len as usize {
            return Err(Error::OutOfRange);
        }

        let mut r = FlashIo::new(&mut flash)?;

        // Container header.
        let len = r.read_le::<u16>()? as usize;
        let magic = r.read_le::<u16>()?;
        let id = r.read_le::<u32>()?;
        let sig_len = r.read_le::<u16>()? as usize;
        // FIXME: Manticore currently ignores this value.
        let _sig_type = r.read_le::<u8>()?;
        let _ = r.read_le::<u8>()?;

        // TOC header.
        let entry_count = r.read_le::<u8>()?;
        let hash_count = r.read_le::<u8>()?;
        let hash_type = r.read_le::<u8>()?;
        let reserved = r.read_le::<u8>()?;

        // FIXME: we don't deal with hash types that aren't SHA-256.
        if hash_type != HashType::Sha256.to_wire_value() {
            return Err(Error::OutOfRange);
        }

        let mut cursor = r.cursor();
        let entries = flash.read_slice::<RawTocEntry>(
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

        let toc = Toc {
            entries,
            hashes,
            _ph: PhantomData,
        };
        if !toc.check_invariants() {
            return Err(Error::OutOfRange);
        }

        // Compute the signature/signed regions for verification later on.
        let sig_offset = len.checked_sub(sig_len).ok_or(Error::OutOfRange)?;
        let sig = Region::new(sig_offset as u32, sig_len as u32);

        let signed_len = sig_offset;
        let signed = Region::new(0, signed_len as u32);

        let container = Self {
            manifest_type: ManifestType::from_wire_value(magic)
                .ok_or(Error::OutOfRange)?,
            metadata: Metadata { version_id: id },
            flash,
            toc,
            _ph: PhantomData,
        };
        Ok((container, sig, signed))
    }

    /// Returns the [`ManifestType`] for this `Container`.
    ///
    /// [`ManifestType`]: ../enum.ManifestType.html
    pub fn manifest_type(&self) -> ManifestType {
        self.manifest_type
    }

    /// Checks whether this `Container` can replace `other`.
    ///
    /// In other words, `self` must:
    /// - Be of the same type as `other`.
    /// - Have a greater or equal `id` number than `other`.
    pub fn can_replace(&self, other: &Self) -> bool {
        self.manifest_type == other.manifest_type
            && self.metadata.version_id >= other.metadata.version_id
    }

    /// Returns this `Container`'s [`Metadata`] value.
    ///
    /// [`Metadata`]: struct.Metadata.html
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Returns this `Container`'s [`Toc`].
    ///
    /// [`Toc`]: struct.Toc.html
    pub fn toc(&self) -> &Toc<'f, M> {
        &self.toc
    }

    /// Returns the backing storage for this `Container`.
    pub fn flash(&self) -> &'f F {
        self.flash
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    use crate::crypto::ring;
    use crate::crypto::rsa::Builder as _;
    use crate::crypto::rsa::Keypair as _;
    use crate::crypto::rsa::SignerBuilder as _;
    use crate::crypto::testdata;
    use crate::hardware::flash::Ram;
    use crate::manifest::owned;
    use crate::manifest::pfm;
    use crate::manifest::pfm::Pfm;
    use crate::mem::OutOfMemory;

    use serde_json::from_str;

    pub fn make_rsa_engine() -> (ring::rsa::Engine, ring::rsa::Signer) {
        let keypair =
            ring::rsa::Keypair::from_pkcs8(testdata::RSA_2048_PRIV_PKCS8)
                .unwrap();
        let pub_key = keypair.public();
        let rsa_builder = ring::rsa::Builder::new();
        let rsa = rsa_builder.new_engine(pub_key).unwrap();
        let signer = rsa_builder.new_signer(keypair).unwrap();
        (rsa, signer)
    }

    // NOTE: To effectively run these tests, we use PFM-from-JSON to generate
    // some of the tests, but they're intended to be independent of the actual
    // manifest type.

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
        type Flash = Ram<Vec<u8>>;

        let container: Container<'_, Pfm<'_, Flash>, Flash> =
            Container::parse_and_verify(
                &bytes,
                &sha,
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
    fn one_element() {
        let sha = ring::sha256::Builder::new();
        let (mut rsa, mut signer) = make_rsa_engine();

        #[rustfmt::skip]
        let pfm: owned::Pfm = from_str(r#"{
            "version_id": 42,
            "elements": [{ "platform_id": "blah" }]
        }"#).unwrap();
        let bytes = Ram(pfm.sign(0x0, &sha, &mut signer).unwrap());
        type Flash = Ram<Vec<u8>>;

        let container: Container<'_, Pfm<'_, Flash>, Flash> =
            Container::parse_and_verify(
                &bytes,
                &sha,
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
        assert_eq!(first.element_type(), pfm::ElementType::PlatformId);
        assert!(first.parent().is_none());
        assert!(first.hash().is_some());
        assert_eq!(first.children().count(), 0);
    }

    #[test]
    fn with_child() {
        let sha = ring::sha256::Builder::new();
        let (mut rsa, mut signer) = make_rsa_engine();

        #[rustfmt::skip]
        let pfm: owned::Pfm = from_str(r#"{
            "version_id": 42,
            "elements": [{
                "platform_id": "blah",
                "children": [{
                    "platform_id": "blah2",
                    "hashed": false
                }]
            }]
        }"#).unwrap();
        let bytes = Ram(pfm.sign(0x0, &sha, &mut signer).unwrap());
        type Flash = Ram<Vec<u8>>;

        let container: Container<'_, Pfm<'_, Flash>, Flash> =
            Container::parse_and_verify(
                &bytes,
                &sha,
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
        assert_eq!(first.element_type(), pfm::ElementType::PlatformId);
        assert!(first.parent().is_none());
        assert!(first.hash().is_some());

        let children = first.children().collect::<Vec<_>>();
        assert_eq!(children.len(), 1);
        let second = children[0];
        assert_eq!(second.index(), 1);
        assert_eq!(second.element_type(), pfm::ElementType::PlatformId);
        assert_eq!(second.parent().unwrap().index(), 0);
        assert!(second.hash().is_none());
    }

    // TODO: Write test that involve pre-baked manifests, as opposed to the
    // dynamically built ones. We don't do this right now because there's a
    // couple of details missing w.r.t making sure we match up with the
    // specified format.
}
