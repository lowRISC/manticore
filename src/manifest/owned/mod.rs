// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Owned manifest containers.
//!
//! This module provides a heap-allocated manifest container, which represents
//! elements as a tree structure. This module is intended for tooling to make
//! building arbitrary manifests easy and straight-forward.
//!
//! When the `serde` feature is enabled, owned manifests can be de/serialized.

use std::collections::HashMap;
use std::convert::TryInto;
use std::mem;

use zerocopy::AsBytes;

use crate::crypto::rsa;
use crate::crypto::sha256;
use crate::io::write::StdWrite;
use crate::io::Read as _;
use crate::io::Write as _;
use crate::manifest::container::RawTocEntry;
use crate::manifest::Error;
use crate::manifest::HashType;
use crate::manifest::ManifestType;
use crate::manifest::Metadata;
use crate::protocol::wire::WireEnum;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod pfm;

/// An "owned" manifest element.
///
/// This trait exists to allow [`owned::Container`] to be generic over
/// different kinds of Cerberus manifest types. In general, users should
/// not have to implement this type.
///
/// `Element::ElementType` and `Element::TYPE` are analogous to the same
/// trait items from [`Manifest`].
///
/// [`owned::Container`]: struct.Container.html
/// [`Manifest`]: ../trait.Manifest.html
#[doc(hidden)]
pub trait Element: Sized {
    /// A `WireEnum` representing the different kinds of valid element types
    /// for a Manifest that Manticore understands.
    type ElementType: WireEnum<Wire = u8>;

    /// The specific value of `ManifestType` representing the type implementing
    /// this trait.
    const TYPE: ManifestType;

    /// Returns the element type of a specific element.
    fn element_type(&self) -> Self::ElementType;

    /// Attempts to construct an `Element` of the given type from encoded
    /// `bytes`.
    fn from_bytes(ty: Self::ElementType, bytes: &[u8]) -> Result<Self, Error>;

    /// Attempts to encode this `Element` into bytes, using the given
    /// padding byte as "filler".
    fn to_bytes(&self, padding_byte: u8) -> Result<Vec<u8>, Error>;
}

/// A heap-allocated PFM.
///
/// See [`manicore::manifest::pfm`] for lazy parsing out of flash.
///
/// [`manticore::manifest::pfm`]: ../pfm/index.html
pub type Pfm = Container<self::pfm::Element>;

/// A heap-allocated Cerberus manifest, represented as a tree structure.
///
/// Prefer to access this type through one of the provided type aliases,
/// instead:
/// - Platform Firmware Manifest: [`Pfm`](type.Pfm.html)
/// - Component Firmware Manifest: NYI
/// - Platform Configuration Descriptor: NYI
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Container<E> {
    /// The metadata for this manifest.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub metadata: Metadata,

    /// The root elements of this manifest.
    pub elements: Vec<Node<E>>,
}

/// An element node within a manifest [`Container`].
///
/// [`Container`] struct.Container.html
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Node<E> {
    /// Whether this node should be hashed.
    #[cfg_attr(
        feature = "serde",
        serde(
            default = "crate::serde::default_to_true",
            skip_serializing_if = "crate::serde::skip_if_true"
        )
    )]
    pub hashed: bool,

    /// The element that this node contains.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub element: E,

    /// This element's children, if any are present.
    #[cfg_attr(
        feature = "serde",
        serde(default = "Vec::new", skip_serializing_if = "Vec::is_empty")
    )]
    pub children: Vec<Node<E>>,
}

/// A parsing result.
///
/// See [`Container::parse()`].
///
/// [`Container::parse()`]: struct.Container.html#method.parse
pub struct Parse<E> {
    /// The container resulting from the parse.
    pub container: Container<E>,

    /// Whether the container had a bad signature.
    pub bad_signature: bool,

    /// Whether the TOC hash was bad.
    pub bad_toc_hash: bool,

    /// A list of indices of TOC entries whose elements had bad hashes.
    pub bad_hashes: Vec<usize>,
}

impl<E: Element> Container<E> {
    /// Parses a `Container` out of `bytes`.
    ///
    /// Note that if a cryptographic operation fails, `Ok` will still be returned;
    /// the resulting value will indicate which operations failed in addition to
    /// containing the parsed container.
    pub fn parse(
        bytes: &[u8],
        sha: &impl sha256::Builder,
        rsa: &mut impl rsa::Engine,
    ) -> Result<Parse<E>, Error> {
        let mut parse = Parse {
            container: Self {
                metadata: Metadata { version_id: 0 },
                elements: Vec::new(),
            },
            bad_signature: false,
            bad_toc_hash: false,
            bad_hashes: Vec::new(),
        };

        // FIXME: Right now we ignore a bunch of "implied" fields in the
        // manifest, but we may want to either reject failures, use them,
        // or simply report them.
        let mut r = bytes;
        let total_len = r.read_le::<u16>()?;
        let _element_type = r.read_le::<u16>()?;
        parse.container.metadata.version_id = r.read_le()?;
        let sig_len = r.read_le::<u16>()?;
        let _sig_type = r.read_le::<u8>()?;
        let _ = r.read_le::<u8>()?;

        let toc_start = bytes.len() - r.len();
        let entry_count = r.read_le::<u8>()?;
        let hash_count = r.read_le::<u8>()?;
        let _hash_type = r.read_le::<u8>()?;
        let _ = r.read_le::<u8>()?;

        let mut toc = Vec::new();
        for _ in 0..entry_count {
            let mut entry = RawTocEntry::default();
            r.read_bytes(entry.as_bytes_mut())?;
            toc.push(entry);
        }

        let mut hashes = Vec::new();
        for _ in 0..hash_count {
            let mut hash = [0; 32];
            r.read_bytes(&mut hash)?;
            hashes.push(hash);
        }
        let toc_end = bytes.len() - r.len();

        let mut expected_toc_hash = [0; 32];
        r.read_bytes(&mut expected_toc_hash)?;

        let mut toc_hash = [0; 32];
        let toc_bytes = &bytes[toc_start..toc_end];
        sha.hash_contiguous(toc_bytes, &mut toc_hash)?;
        parse.bad_toc_hash = toc_hash != expected_toc_hash;

        for (i, entry) in toc.iter().enumerate() {
            if entry.hash_idx == 0xff {
                continue;
            }
            let expected = hashes
                .get(entry.hash_idx as usize)
                .ok_or(Error::OutOfRange)?;

            let start = entry.offset as usize;
            let end = start + entry.len as usize;
            let bytes = bytes.get(start..end).ok_or(Error::OutOfRange)?;

            let mut hash = [0; 32];
            sha.hash_contiguous(bytes, &mut hash)?;
            if &hash != expected {
                parse.bad_hashes.push(i);
            }
        }

        let sig_start =
            total_len.checked_sub(sig_len).ok_or(Error::OutOfRange)? as usize;
        let sig_end = total_len as usize;
        let signed = bytes.get(..sig_start).ok_or(Error::OutOfRange)?;
        let sig = bytes.get(sig_start..sig_end).ok_or(Error::OutOfRange)?;

        let mut signed_hash = [0; 32];
        sha.hash_contiguous(&signed, &mut signed_hash)?;
        parse.bad_signature = rsa.verify_signature(sig, &signed_hash).is_err();

        // Build a table of parent index -> element, to help us build the
        // tree of elements.
        let mut parents = HashMap::<usize, Vec<usize>>::new();
        for (idx, entry) in toc.iter().enumerate() {
            parents
                .entry(entry.parent_idx as usize)
                .or_default()
                .push(idx);
        }

        build_tree(0xff, bytes, &toc, &parents, &mut parse.container.elements)?;
        fn build_tree<E: Element>(
            parent: usize,
            bytes: &[u8],
            toc: &[RawTocEntry],
            parents: &HashMap<usize, Vec<usize>>,
            elements: &mut Vec<Node<E>>,
        ) -> Result<(), Error> {
            for i in parents.get(&parent).as_deref().unwrap_or(&Vec::new()) {
                let toc_entry = toc.get(*i).ok_or(Error::OutOfRange)?;
                let ty = <E::ElementType as WireEnum>::from_wire_value(
                    toc_entry.element_type,
                )
                .ok_or(Error::OutOfRange)?;

                let start = toc_entry.offset as usize;
                let end = start + toc_entry.len as usize;
                let entry_bytes =
                    bytes.get(start..end).ok_or(Error::OutOfRange)?;
                let element = E::from_bytes(ty, entry_bytes)?;

                let mut node = Node {
                    element,
                    children: Vec::new(),
                    hashed: toc_entry.hash_idx != 0xff,
                };

                // FIXME: Cycle detection.
                build_tree(*i, bytes, toc, parents, &mut node.children)?;
                elements.push(node);
            }
            Ok(())
        }

        Ok(parse)
    }
    /// Signs this `Container` using the given cryptographic primitives.
    ///
    /// `padding_byte` is the byte inserted to pad each element to a
    /// four-byte alignment; usually this will want to be `0x00` or `0xff.
    pub fn sign(
        &self,
        padding_byte: u8,
        sha: &impl sha256::Builder,
        rsa: &mut impl rsa::Signer,
    ) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        let mut w = StdWrite(&mut bytes);
        w.write_le(0u16)?; // To be filled in later.
        w.write_le(E::TYPE.to_wire_value())?;
        w.write_le(self.metadata.version_id)?;
        w.write_le(rsa.pub_len().byte_len() as u16)?;
        w.write_le(0u8)?; // Should be sig_type.
        w.write_le(padding_byte)?;

        let mut index = 0;
        let mut hash_index = 0;
        let mut offset = 0;
        let mut encoded = Vec::new();
        encode_elements(
            &self.elements,
            padding_byte,
            0xff,
            &mut index,
            &mut hash_index,
            &mut offset,
            &mut encoded,
        )?;

        /// Recursive helper for linearizing the tree of elements in `self`.
        fn encode_elements<E: Element>(
            nodes: &[Node<E>],
            padding_byte: u8,
            parent_index: u8,
            index: &mut u8,
            hash_index: &mut u8,
            offset: &mut u16,
            out: &mut Vec<(RawTocEntry, Vec<u8>)>,
        ) -> Result<(), Error> {
            for node in nodes {
                if node.hashed && *hash_index == 0xff {
                    return Err(Error::OutOfRange);
                }
                if !node.children.is_empty() && *index == 0xff {
                    return Err(Error::OutOfRange);
                }

                let data = node.element.to_bytes(padding_byte)?;
                let len =
                    data.len().try_into().map_err(|_| Error::OutOfRange)?;
                let entry = RawTocEntry {
                    element_type: node.element.element_type().to_wire_value(),
                    format_version: 0, // FIXME.
                    offset: *offset,
                    len,
                    parent_idx: parent_index,
                    hash_idx: if node.hashed { *hash_index } else { 0xff },
                };

                *index = index.checked_add(1).ok_or(Error::OutOfRange)?;
                *offset = offset.checked_add(len).ok_or(Error::OutOfRange)?;
                if node.hashed {
                    *hash_index += 1;
                }

                out.push((entry, data));

                let this_index = *index - 1;
                encode_elements(
                    &node.children,
                    padding_byte,
                    this_index,
                    index,
                    hash_index,
                    offset,
                    out,
                )?;
            }
            Ok(())
        }

        let mut toc = vec![
            index,
            hash_index,
            HashType::Sha256.to_wire_value(),
            padding_byte,
        ];
        let mut toc_hashes = Vec::with_capacity(
            mem::size_of::<sha256::Digest>() * hash_index as usize,
        );

        let header_len = bytes.len()
            + toc.len()
            + encoded.len() * mem::size_of::<RawTocEntry>()
            + (hash_index as usize + 1) * mem::size_of::<sha256::Digest>();
        let header_len: u16 =
            header_len.try_into().map_err(|_| Error::OutOfRange)?;

        for (entry, data) in &mut encoded {
            entry.offset = entry
                .offset
                .checked_add(header_len)
                .ok_or(Error::OutOfRange)?;
            toc.extend_from_slice(entry.as_bytes());

            if entry.hash_idx != 0xff {
                let mut hash = [0; 32];
                sha.hash_contiguous(data, &mut hash)?;
                toc_hashes.extend_from_slice(&hash);
            }
        }
        toc.extend_from_slice(&toc_hashes);
        let mut toc_hash = [0; 32];
        sha.hash_contiguous(&toc, &mut toc_hash)?;
        bytes.extend_from_slice(&toc);
        bytes.extend_from_slice(&toc_hash);

        for (_, data) in &encoded {
            bytes.extend_from_slice(data);
        }

        let total_len: u16 = (bytes.len() + rsa.pub_len().byte_len())
            .try_into()
            .map_err(|_| Error::OutOfRange)?;
        bytes[0..2].copy_from_slice(&total_len.to_le_bytes());

        let mut signed = [0; 32];
        let mut signature = vec![0; rsa.pub_len().byte_len()];
        sha.hash_contiguous(&bytes, &mut signed)?;
        rsa.sign(&signed, &mut signature)?;
        bytes.extend_from_slice(&signature);

        Ok(bytes)
    }
}
