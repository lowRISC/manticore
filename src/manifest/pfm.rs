// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! TODO

#![allow(unused_imports)]

use core::mem;

use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::crypto::sha256;
use crate::crypto::sha256::Hasher as _;
use crate::hardware::flash::Flash;
use crate::hardware::flash::FlashExt as _;
use crate::hardware::flash::FlashIo;
use crate::hardware::flash::Ptr;
use crate::hardware::flash::Region;
use crate::hardware::flash::SubFlash;
use crate::io::Read as _;
use crate::manifest::container::Container;
use crate::manifest::provenance;
use crate::manifest::Error;
use crate::mem::Arena;
use crate::mem::ArenaExt as _;
use crate::protocol::wire::WireEnum;

wire_enum! {
    /// A PFM element type.
    pub enum ElementType: u8 {
      /// TODO
      FlashDevice = 0x00,

      /// TODO
      AllowableFw = 0x01,

      /// TODO
      FwVersion = 0x02,

      /// TODO
      PlatformId = 0x03,
    }
}

wire_enum! {
    /// TODO
    pub enum HashType: u8 {
      /// TODO
      Sha256 = 0b000,
      // Sha384 = 0b001,
      // Sha512 = 0b010,
    }
}

/// TODO
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

impl TocEntry {
    /// TODO
    pub fn element_type(&self) -> Option<ElementType> {
        ElementType::from_wire_value(self.element_type)
    }

    /// TODO
    pub fn format_version(&self) -> u8 {
        self.format_version
    }

    /// TODO
    pub fn offset(&self) -> usize {
        self.offset as _
    }

    /// TODO
    pub fn len(&self) -> usize {
        self.len as _
    }

    /// TODO
    pub fn parent_idx(&self) -> Option<usize> {
        match self.parent_idx {
            0xff => None,
            x => Some(x as _),
        }
    }

    /// TODO
    pub fn hash_idx(&self) -> Option<usize> {
        match self.hash_idx {
            0xff => None,
            x => Some(x as _),
        }
    }
}

/// TODO
pub struct Pfm<'arena, 'flash, Flash> {
    entries: &'arena [TocEntry],
    hashes: &'arena [sha256::Digest],
    flash: SubFlash<&'flash Flash>,
}

impl<'arena, 'flash: 'arena, F: Flash> Pfm<'arena, 'flash, F> {
    /// Parses the table of contents of a PFM.
    pub fn parse(
        container: &'flash Container<F, provenance::Signed>,
        sha: &impl sha256::Builder,
        arena: &'arena impl Arena,
    ) -> Result<Self, Error> {
        let flash = SubFlash(container.flash(), container.body());

        let mut io = FlashIo::new(flash)?;
        let entry_count = io.read_le::<u8>()? as usize;
        let hash_count = io.read_le::<u8>()? as usize;
        let hash_type = io.read_le::<u8>()? as usize;
        // FIXME: we don't deal with hash types that aren't SHA-256.
        if hash_type != 0 {
            return Err(Error::OutOfRange);
        }

        let entry_bytes = mem::size_of::<TocEntry>() * entry_count;
        let hash_bytes = mem::size_of::<sha256::Digest>() * hash_count;
        let total_len = 4 + entry_bytes + hash_bytes;

        let mut expected_hash = [0; 32];
        flash.read(Ptr::new(total_len as u32), &mut expected_hash)?;

        let mut hasher =
            sha.new_hasher().map_err(|_| Error::SignatureFailure)?;
        let iter = FlashIo::new(
            flash
                .reslice(Region::new(0, total_len as u32))
                .ok_or(Error::OutOfRange)?,
        )?;
        for byte in iter {
            hasher
                .write(&[byte?])
                .map_err(|_| Error::SignatureFailure)?;
        }
        let mut hash = [0; 32];
        hasher
            .finish(&mut hash)
            .map_err(|_| Error::SignatureFailure)?;

        if hash != expected_hash {
            return Err(Error::SignatureFailure);
        }

        let entries = flash.0.read_slice::<TocEntry>(
            Ptr::new(flash.1.ptr.address + mem::size_of::<u32>() as u32),
            entry_count,
            arena,
        )?;
        let hashes = flash.0.read_slice::<sha256::Digest>(
            Ptr::new(
                flash.1.ptr.address
                    + (mem::size_of::<u32>() + entry_bytes) as u32,
            ),
            hash_count,
            arena,
        )?;
        Ok(Pfm {
            entries,
            hashes,
            flash,
        })
    }

    /// Extracts the Platform ID from this PFM, allocating it onto the provided
    /// arena. Returns `None` if the Platform ID is missing.
    ///
    /// This function will also verify the hash of the Platform ID, if one is
    /// present.
    pub fn platform_id<'id_arena: 'id, 'id>(
        &mut self,
        sha: &impl sha256::Builder,
        arena: &'id_arena impl Arena,
    ) -> Result<Option<&'id [u8]>, Error>
    where
        'flash: 'id,
    {
        let entry = match self
            .entries
            .iter()
            .find(|e| e.element_type() == Some(ElementType::PlatformId))
        {
            Some(x) => x,
            None => return Ok(None),
        };

        let element = SubFlash(
            self.flash,
            Region::new(entry.offset() as u32, entry.len() as u32),
        );

        if let Some(hash_idx) = entry.hash_idx() {
            let expected =
                self.hashes.get(hash_idx).ok_or(Error::SignatureFailure)?;

            let mut hasher =
                sha.new_hasher().map_err(|_| Error::SignatureFailure)?;
            for byte in FlashIo::new(element)? {
                hasher
                    .write(&[byte?])
                    .map_err(|_| Error::SignatureFailure)?;
            }

            let mut hash = [0; 32];
            hasher
                .finish(&mut hash)
                .map_err(|_| Error::SignatureFailure)?;
            if &hash != expected {
                return Err(Error::SignatureFailure);
            }
        }

        // TODO: improve Read APIs to make this cleaner while allowing for
        // use of read_direct().
        let mut len_bytes = [0; 2];
        element.read(Ptr::new(0), &mut len_bytes)?;
        let len = u16::from_le_bytes(len_bytes);

        Ok(Some(self.flash.0.read_slice::<u8>(
            Ptr::new(self.flash.1.ptr.address + entry.offset() as u32 + 4),
            len as usize,
            arena,
        )?))
    }
}
