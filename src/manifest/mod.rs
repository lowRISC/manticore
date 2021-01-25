// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cerberus manifest manipulation.
//!
//! Cerberus uses a number of signed "manifests" to describe both the physical
//! configuration of a system it protects, and to describe policies on what
//! firmware can run on those systems.

use crate::crypto::rsa;
use crate::crypto::sha256;
use crate::hardware::flash;
use crate::io;
use crate::mem::OutOfMemory;

pub mod container;
pub mod pfm;

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

/// An error returned by a manifestoperation.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Indicates an error in a low-level [`io`] type.
    ///
    /// [`io`]: ../io/index.html
    Io(io::Error),
    /// Indicates that an error occured in a [`flash`] type.
    ///
    /// [`flash`]: ../hardware/flash/html
    Flash(flash::Error),
    /// Indicates that an arena ran out of memory.
    OutOfMemory,
    /// Indicates that a value was out of its expected range.
    OutOfRange,
    /// Indicates that some assumption about a manifest's alignment (internal
    /// or overall) was violated.
    Unaligned,
    /// Indicates that a signature operation failed for some reason.
    SignatureFailure,
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

impl<E> From<rsa::Error<E>> for Error {
    fn from(_: rsa::Error<E>) -> Self {
        Self::SignatureFailure
    }
}

impl<E> From<sha256::Error<E>> for Error {
    fn from(_: sha256::Error<E>) -> Self {
        Self::SignatureFailure
    }
}

/// Manifest provenances.
///
/// A *provenance* is a marker type used to indicate the source of a parsed
/// manifest, to help ensure that manifest signatures are properly checked
/// before the manifest is used.
///
/// These types are only really intended to be used as type parameters.
pub mod provenance {
    /// The "signed" provenance, indicating a manifest that has been
    /// appropriately verified.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub enum Signed {}

    /// The "ad-hoc" provenance, indicating a manifest that came from
    /// "somewhere else", such as `serde` or manual construction.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub enum Adhoc {}
}
