// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cerberus manifest manipulation.
//!
//! Cerberus uses a number of signed "manifests" to describe both the physical
//! configuration of a system it protects, and to describe policies on what
//! firmware can run on those systems.

use crate::io;

pub mod container;
pub mod fpm;

wire_enum! {
    /// A Cerberus manifest type.
    ///
    /// This enum represents the "magic number" `u16` value in a maniest header.
    pub enum ManifestType: u16 {
        /// A ["Firmware Policy Manifest"], a Manticore-specific variant of the
        /// PFM.
        ///
        /// ["Firmware Policy Manifest"]: fpm/index.html
        Fpm = 0xda0e,
    }
}

/// An error returned by a manifest parsing operation.
#[derive(Clone, Copy, Debug)]
pub enum ParseError {
    /// Indicates an error in a low-level [`io`] type.
    ///
    /// [`io`]: ../io/index.html
    Io(io::Error),
    /// Indicates that a parsed value was out of its expected range, like a
    /// magic number.
    OutOfRange,
    /// Indicates that some assumption about a manifest's alignment (internal
    /// or overall) was violated.
    Unaligned,
    /// Indicates that a signature verification failed for some reason.
    SignatureFailure,
}

impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn take_bytes<'m>(r: &mut &'m [u8], n: usize) -> Result<&'m [u8], io::Error> {
    if r.len() < n {
        return Err(io::Error::BufferExhausted);
    }
    let (bytes, rest) = r.split_at(n);
    *r = rest;
    Ok(bytes)
}

/// Reads exactly `n * size_of::<T>` bytes from `r`, and converts them
/// into a slice of `T`s.
///
/// Moreover, this function requires that the next pointer that would be
/// returned by `read_bytes()` is well-aligned for `T`; otherwise,
/// `ParseError::Unaligned` is returned.
fn read_zerocopy<'m, T: zerocopy::FromBytes>(
    r: &mut &'m [u8],
    count: usize,
) -> Result<&'m [T], ParseError> {
    let expected_len = core::mem::size_of::<T>()
        .checked_mul(count)
        .ok_or(io::Error::BufferExhausted)?;
    let bytes = take_bytes(r, expected_len)?;
    let layout = zerocopy::LayoutVerified::new_slice(bytes)
        .ok_or(ParseError::Unaligned)?;
    Ok(layout.into_slice())
}
