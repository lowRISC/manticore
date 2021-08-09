// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cerberus manifest manipulation.
//!
//! Cerberus uses a number of signed "manifests" to describe both the physical
//! configuration of a system it protects, and to describe policies on what
//! firmware can run on those systems.
//!
//! # Wire Format
//!
//! On the wire (and in flash) every manifest has the following layout,
//! expressed as a pseudo-Rust struct. Integers are encoded in little-endian
//! order, and `_` indicates reserved fields or padding that should be set
//! to 0.
//! ```ignore
//! struct Manifest {
//!     // Overall header.
//!     total_len: u16,
//!     manifest_type: u16, // See `ManifestType`.
//!     version_id: u32,
//!     signature_len: u16,
//!     signature_type: u8,
//!     _: u8,
//!
//!     // Table-of-contents.
//!     entry_count: u8,
//!     hash_count: u8,
//!     hash_type: u8,
//!     _: u8,
//!     toc: [TocEntry; self.entry_count],
//!     hashes: [Hash<hash_type>; self.hash_count + 1],
//!
//!     body: [u8],
//!
//!     signature: [u8; self.signature_len],
//! }
//!
//! struct TocEntry {
//!     element_type: u8, // See `Manifest::ElementType`.
//!     parent: u8,
//!     format_version: u8,
//!     hash_id: u8,
//!     offset: u16,
//!     length: u16,
//! }
//! ```
//!
//! Each manifest consists of a number of "elements", whose format is
//! manifest-specific. The "table of contents" defines these elements; each
//! entry includes:
//! - The offset and length within the manifest corresponding to it.
//! - The encoding, given by the type and the format version.
//! - An optional parent index, referring to another element in the TOC
//!   (no parent indicated by `0xff`).
//! - An optional hash index, referring to a hash in the TOC's hash list.
//!   (Again, no hash indicated by `0xff`).
//!
//! The final hash in the list of hashes is a hash of the whole TOC.
//! For more information on how to interact with the `TOC`, see
//! the [`Toc`](struct.Toc.html) type.
//!
//! # Parsing and Encoding APIs
//!
//! The `manticore::manifest` module provides an API for reading a manifest
//! stored in remote flash with minimal memory overhead, allowing the caller
//! to specify which arena various book-keeping information should be allocated
//! in. The [`Container`] type is the entry-point for this functionality.
//!
//! This module also provides an "owned" API that eagerly parses the manifest
//! into a tree based on his TOC. This requires the `std` feature, and is intended
//! for use by tooling. The [`owned::Container`] type is the relevant entry
//! point.

use crate::crypto::hash;
use crate::crypto::sig;
use crate::hardware::flash;
use crate::io;
use crate::mem::OutOfMemory;
use crate::protocol::wire::WireEnum;

mod container;
pub use container::Container;
pub use container::Metadata;
pub use container::Toc;
pub use container::TocEntry;

mod generic;
pub use generic::*;

#[cfg(feature = "std")]
pub mod owned;
pub mod pfm;

#[cfg(test)]
mod testdata;

#[cfg(doc)]
use crate::hardware::flash::Flash;

wire_enum! {
    /// A Cerberus manifest type.
    ///
    /// This enum represents the "magic number" `u16` value in a maniest header.
    pub enum ManifestType: u16 {
        /// A ["Platform Firmware Manifest"], a manifest which describes
        /// firmware that is allowed to run on a platfrom.
        ///
        /// ["Platform Firmware Manifest"]: pfm/index.html
        Pfm = 0x706d,
    }
}

/// A manifest element type.
///
/// In general, you'll want to work with [`ElementsOf`] instead.
///
/// There are three kinds of element types:
/// - Types shared by all manifests.
/// - Types specific to a manifest (see [`ElementType::Specific`]).
/// - Vendor-defined types (see [`ElementType::Vendor`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ElementType<Specific> {
    /// A bytestring describing the platform a manifest is intended for.
    PlatformId,

    /// A manifest-specific element type.
    Specific(Specific),

    /// A vendor-defined type, in the range `0xe0..=0xfe`.
    Vendor(u8),
}

// We can't use macro, unfortunately.
impl<S: WireEnum<Wire = u8>> WireEnum for ElementType<S> {
    type Wire = u8;

    fn to_wire_value(self) -> Self::Wire {
        match self {
            Self::PlatformId => 0x00,
            Self::Specific(s) => s.to_wire_value(),
            Self::Vendor(v) => v,
        }
    }

    fn from_wire_value(wire: Self::Wire) -> Option<Self> {
        match wire {
            0x00 => Some(Self::PlatformId),
            0x01..=0x0f | 0xff => None,
            0xe0..=0xfe => Some(Self::Vendor(wire)),
            _ => S::from_wire_value(wire).map(Self::Specific),
        }
    }
}

impl<S> From<S> for ElementType<S> {
    fn from(s: S) -> Self {
        Self::Specific(s)
    }
}

/// Convenience alias for obtaining the full [`ElementType`] for a manifest.
pub type ElementsOf<M> = ElementType<<M as Manifest>::ElementType>;

/// An error returned by a manifestoperation.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Indicates an error in a low-level [`io`] type.
    Io(io::Error),

    /// Indicates that an error occured in a [`flash`] type.
    Flash(flash::Error),

    /// Indicates that an arena ran out of memory.
    OutOfMemory,

    /// Indicates that a value was out of its expected range.
    OutOfRange,

    /// Indicates that a manifest's magic value did not match the
    /// expected one for this manifest type.
    ///
    /// Contains the bad value found.
    BadMagic(u16),

    /// Indicates that the overall TOC hash did not match the actual value.
    BadTocHash(hash::Error),

    /// Indicates that a TOC entry in the manifest had an invalid parent.
    BadParent {
        /// The index of the bad entry.
        toc_index: usize,
    },

    /// Indicates that a TOC entry in the manifest had an out-of-range
    /// hash index.
    BadHashIndex {
        /// The index of the bad entry.
        toc_index: usize,
    },

    /// Indicates that a TOC entry's hash did not match the actual value.
    BadElementHash {
        /// The reason for the failure.
        error: hash::Error,
        /// The index of the bad entry.
        toc_index: usize,
    },

    /// Indicates that parsing of a particular element failed because it was
    /// below the minimum length.
    TooShort {
        /// The index of the bad entry.
        toc_index: usize,
    },

    /// Indicates a bad range was found while parsing a particular element.
    ///
    /// This indicates that the given range, given as a start and an end, would
    /// have had negative length.
    BadRange {
        /// The index of the bad entry.
        toc_index: usize,
    },

    /// Indicates that some assumption about a manifest's alignment (internal
    /// or overall) was violated.
    Unaligned,

    /// Indicates that a manifest contained a signature type not supported by
    /// the hash engine being used.
    UnsupportedHashType(hash::Algo),

    /// Indicates that the signature length is incompatible with either the
    /// given manifest length or the signature algorithm.
    BadSignatureLen,

    /// Indicates that an error occured inside of a hashing engine.
    HashError(hash::Error),

    /// Indicates that a signature operation failed for some reason.
    SigError(sig::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<flash::Error> for Error {
    fn from(e: flash::Error) -> Self {
        Self::Flash(e)
    }
}

impl From<OutOfMemory> for Error {
    fn from(_: OutOfMemory) -> Self {
        Self::OutOfMemory
    }
}

impl From<sig::Error> for Error {
    fn from(e: sig::Error) -> Self {
        Self::SigError(e)
    }
}

impl From<hash::Error> for Error {
    fn from(e: hash::Error) -> Self {
        Self::HashError(e)
    }
}

debug_from!(Error => io::Error, flash::Error, OutOfMemory, sig::Error, hash::Error);

/// A manifest type.
///
/// A type that implements this trait is not itself a "parsed" instance of the
/// manifest. Rather, it is a sort of marker type that records static
/// information about the manifest type.
///
/// For example [`pfm::Pfm`] implements `Manifest`, but is not an instantiable
/// type. When projected through [`Parse`] with a specific [`Flash`] type,
/// [`Parse::Parsed`] is [`pfm::ParsedPfm<...>`] with appropriate choices for
/// the type parameters.
pub trait Manifest: Sized {
    /// A `WireEnum` representing the different kinds of valid element types
    /// for a Manifest that Manticore understands.
    type ElementType: WireEnum<Wire = u8>;

    /// The specific value of `ManifestType` representing the type implementing
    /// this trait.
    const TYPE: ManifestType;

    /// The minimum version of a particular `ElementType` understood by
    /// Manticore. All manifest elements must be future-compatible, so knowing
    /// a "maximum version" is not necessary.
    fn min_version(ty: Self::ElementType) -> u8;
}

/// A moment in which a [`Parse`]able manifest is validated.
///
/// Some manifests may choose to skip parts of the validation process on
/// startup; this enum is used to indicate when validation is occurring to
/// [`Parse::validate()`].
pub enum ValidationTime {
    /// Indicates "startup", i.e., a manifest already present in device flash
    /// is being parsed. Some integrations may choose to skip validation at
    /// this stage.
    Startup,
    /// Indicates "activation", i.e., when a manifest that came from the
    /// outside world is about to replace the current one. All checks are
    /// performed at this time.
    Activation,
}

/// A subtrait of [`Manifest`] that describes how to parse a manifest from a
/// specific [`Container`] specialization.
///
/// Users of this trait should, given `M: Manifest`
/// in a function signature, include a further bound of
/// `M: Parse<'f, ...>` to obtain the appropriate specialized parsing
/// function.
pub trait Parse<'f, Provenance>: Manifest {
    /// The actual type the parsing operation produces.
    type Parsed: ParsedManifest;

    /// Parses a manifest of this type out of `container`.
    fn parse(
        container: Container<'f, Self, Provenance>,
    ) -> Result<Self::Parsed, Error>;

    /// Returns the container wrapped by a parsed manifest.
    ///
    /// See [`ManifestExt::container()`].
    fn container(manifest: &Self::Parsed) -> &Container<'f, Self, Provenance>;

    /// The type of data this manifest guards.
    type Guarded;
    /// Validates that `manifest` is "valid"; that is, whatever state of
    /// the system this manifest protects is consistent with the manifest's
    /// expectation.
    ///
    /// Some manifests may not have anything interesting to do here; in that
    /// case `Self::Guarded` should be `()` and this function should do
    /// nothing.
    fn validate(
        manifest: &Self::Parsed,
        when: ValidationTime,
        args: &Self::Guarded,
    ) -> Result<(), Error>;
}

/// A trait for providing a reverse mapping from a [`Parse::Parsed`] type back
/// to the [`Manifest`] marker type.
pub trait ParsedManifest: Sized {
    /// The [`Manifest`] type associated with this manifest.
    type Manifest: Manifest;
}

/// Manifest provenances.
///
/// A *provenance* is a marker type used to indicate the source of a parsed
/// manifest, to help ensure that manifest signatures are properly checked
/// before the manifest is used.
///
/// These types are only really intended to be used as type parameters.
pub mod provenance {
    /// A provenance. This trait can be used to write code that is generic
    /// on provenances but which might choose to skip certain operations for
    /// the `Adhoc` provenenace.
    pub trait Provenance: 'static {
        /// Whether this provenance represents an authenticated source,
        /// i.e., whether it comes from a continuous chain of trust (via
        /// hashes) to a signature.
        const AUTHENTICATED: bool;
    }

    /// The "signed" provenance, indicating a manifest that has been
    /// appropriately verified.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub enum Signed {}

    impl Provenance for Signed {
        const AUTHENTICATED: bool = true;
    }

    /// The "ad-hoc" provenance, indicating a manifest that came from
    /// "somewhere else", such as `serde` or manual construction.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub enum Adhoc {}

    impl Provenance for Adhoc {
        const AUTHENTICATED: bool = false;
    }
}
