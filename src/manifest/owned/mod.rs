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

use std::convert::TryInto;
use std::mem;

use zerocopy::AsBytes;

use crate::crypto::rsa;
use crate::crypto::sha256;
use crate::hardware::flash::Flash;
use crate::hardware::flash::Ram;
use crate::io::write::StdWrite;
use crate::io::Write as _;
use crate::manifest;
use crate::manifest::container::RawTocEntry;
use crate::manifest::provenance;
use crate::manifest::Error;
use crate::manifest::HashType;
use crate::manifest::Manifest;
use crate::manifest::ManifestType;
use crate::manifest::Metadata;
use crate::mem::OutOfMemory;
use crate::protocol::wire::WireEnum;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod pfm;

/// An "owned" manifest element.
///
/// This trait exists to allow [`owned::Container`] to be generic over
/// different kinds of Cerberus manifest types. In general, users should
/// not have to implement this trait.
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

    /// Attempts to encode this `Element` into bytes, using the given
    /// padding byte as "filler".
    fn to_bytes(&self, padding_byte: u8) -> Result<Vec<u8>, EncodingError>;
}

/// An "owned" manifest element that can be built from its unowned counterpart.
///
/// In general, users should not have to implement this trait.
#[doc(hidden)]
pub trait FromUnowned<'f, F: Flash>: Element {
    /// The "unowned" type.
    type Manifest: Manifest;

    /// Walks a parsed container of this manifest type, building a tree of
    /// elements along the way.
    fn from_container(
        container: manifest::Container<
            'f,
            Self::Manifest,
            F,
            provenance::Adhoc,
        >,
    ) -> Result<Vec<Node<Self>>, Error>;
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

/// An error returned by an encoding operation.
#[derive(Clone, Debug)]
pub enum EncodingError {
    /// Indicates that the manifest had more elements than could be encoded,
    /// due to hard limits in the manifest format.
    ///
    /// This error may refer too top-level elements in the manifest itself,
    /// or a variable-length portion of a manifest element.
    TooManyElements,

    /// Indicates that the manifest would simply be unable to fit the necessary
    /// data (i.e., a length overflowed 16 bits).
    OutOfSpace,

    /// Indicates that a byte string to encode was too long.
    ///
    /// The bad string is included in the error.
    StringTooLong(Vec<u8>),

    /// Indicates a range was empty when it shouldn't have been.
    EmptyRegion,

    /// Indicates an error while computing a hash.
    HashError(sha256::Error),

    /// Indicates an error while computing an RSA signature.
    RsaError(rsa::Error),
}

impl<E> From<sha256::Error<E>> for EncodingError {
    fn from(e: sha256::Error<E>) -> Self {
        Self::HashError(e.erased())
    }
}

impl<E> From<rsa::Error<E>> for EncodingError {
    fn from(e: rsa::Error<E>) -> Self {
        Self::RsaError(e.erased())
    }
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
        rsa: Option<&mut impl rsa::Engine>,
    ) -> Result<Parse<E>, Error>
    where
        E: for<'f> FromUnowned<'f, Ram<&'f [u8]>>,
    {
        let mut parse = Parse {
            container: Self {
                metadata: Metadata { version_id: 0 },
                elements: Vec::new(),
            },
            bad_signature: false,
            bad_toc_hash: false,
            bad_hashes: Vec::new(),
        };

        let ram = Ram(bytes);
        let container = manifest::Container::<
            '_,
            E::Manifest,
            _,
            provenance::Adhoc,
        >::parse(&ram, &OutOfMemory)?;
        // TODO(#58): Right now we ignore a bunch of "implied" fields in the
        // manifest, but we may want to either reject failures, use them,
        // or simply report them.

        parse.container.metadata = container.metadata();
        parse.bad_toc_hash = container.verify_toc_hash(sha).is_err();
        if let Some(rsa) = rsa {
            parse.bad_signature =
                container.verify_signature(sha, rsa, &OutOfMemory).is_err();
        }

        for (i, entry) in container.toc().entries().enumerate() {
            let expected = match entry.hash() {
                Some(h) => h,
                None => continue,
            };

            let region = entry.region();
            let start = region.offset as usize;
            let end = region.end() as usize;
            let bytes = bytes
                .get(start..end)
                .ok_or(Error::TooShort { toc_index: i })?;

            let mut hash = [0; 32];
            sha.hash_contiguous(bytes, &mut hash)?;
            if &hash != expected {
                parse.bad_hashes.push(i);
            }
        }

        parse.container.elements = E::from_container(container)?;
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
    ) -> Result<Vec<u8>, EncodingError> {
        let mut bytes = Vec::new();
        let mut w = StdWrite(&mut bytes);

        // NOTE: because we're writing to a vector, none of these can fail.
        let _ = w.write_le(0u16); // To be filled in later.
        let _ = w.write_le(E::TYPE.to_wire_value());
        let _ = w.write_le(self.metadata.version_id);
        let _ = w.write_le(rsa.pub_len().byte_len() as u16);
        let _ = w.write_le(0u8); // Should be sig_type.
        let _ = w.write_le(padding_byte);

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
            parent_type: u8,
            index: &mut u8,
            hash_index: &mut u8,
            offset: &mut u16,
            out: &mut Vec<(RawTocEntry, Vec<u8>)>,
        ) -> Result<(), EncodingError> {
            for node in nodes {
                // We've run out of hash slots, so this manifest is
                // unencodeable.
                if node.hashed && *hash_index == 0xff {
                    return Err(EncodingError::TooManyElements);
                }

                // Same here: we've run out of parent indices.
                if !node.children.is_empty() && *index == 0xff {
                    return Err(EncodingError::TooManyElements);
                }

                let data = node.element.to_bytes(padding_byte)?;
                let len = data
                    .len()
                    .try_into()
                    .map_err(|_| EncodingError::OutOfSpace)?;

                let element_type = node.element.element_type().to_wire_value();
                let entry = RawTocEntry {
                    element_type,
                    format_version: 0, // TODO(#59)
                    offset: *offset,
                    len,
                    parent_type,
                    hash_idx: if node.hashed { *hash_index } else { 0xff },
                };

                *index = index
                    .checked_add(1)
                    .ok_or(EncodingError::TooManyElements)?;
                *offset =
                    offset.checked_add(len).ok_or(EncodingError::OutOfSpace)?;
                if node.hashed {
                    *hash_index += 1;
                }

                out.push((entry, data));

                encode_elements(
                    &node.children,
                    padding_byte,
                    element_type,
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
        let header_len: u16 = header_len
            .try_into()
            .map_err(|_| EncodingError::OutOfSpace)?;

        for (entry, data) in &mut encoded {
            entry.offset = entry
                .offset
                .checked_add(header_len)
                .ok_or(EncodingError::OutOfSpace)?;
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
            .map_err(|_| EncodingError::OutOfSpace)?;
        bytes[0..2].copy_from_slice(&total_len.to_le_bytes());

        let mut signed = [0; 32];
        let mut signature = vec![0; rsa.pub_len().byte_len()];
        sha.hash_contiguous(&bytes, &mut signed)?;
        rsa.sign(&signed, &mut signature)?;
        bytes.extend_from_slice(&signature);

        Ok(bytes)
    }
}
