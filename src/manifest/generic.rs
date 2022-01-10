// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Extension traits for manifest-generic operations.

use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::crypto::hash;
use crate::hardware::flash::Flash;
use crate::manifest::provenance::Provenance;
use crate::manifest::Container;
use crate::manifest::ElementType;
use crate::manifest::Error;
use crate::manifest::Parse;
use crate::manifest::ParsedManifest;
use crate::manifest::TocEntry;
use crate::mem::Arena;
use crate::Result;

/// An identifier for the platform a manifest is for.
pub struct PlatformId<'a, 'f, Manifest> {
    entry: TocEntry<'a, 'f, Manifest>,
    id: &'f [u8],
}

impl<'a, 'f, Manifest> PlatformId<'a, 'f, Manifest> {
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'f, Manifest> {
        self.entry
    }

    /// Returns the byte-string identifier that represents the platform a
    /// manifest is for.
    pub fn id_string(&self) -> &'f [u8] {
        self.id
    }
}

/// Helpers for working with manifests.
#[extend::ext(name = ManifestExt)]
pub impl<'f, P, M> M
where
    P: Provenance,
    M: ParsedManifest,
    M::Manifest: Parse<'f, P, Parsed = Self>,
{
    /// Gets the [`Container`] that this manifest wraps.
    fn container(&self) -> &Container<'f, M::Manifest, P> {
        M::Manifest::container(self)
    }

    /// Copies the serialized contents of `self` to `dest`.
    ///
    /// `dest` may be an altogether different flash type from the one
    /// `self` originated from.
    fn copy_to(&self, dest: &mut impl Flash) -> Result<(), Error> {
        let src = self.container().flash();
        let len = src.size()? as usize;
        let mut bytes_left = len;

        let mut buf = [0; 32];
        while bytes_left > 0 {
            let bytes_to_copy = bytes_left.min(buf.len());
            let buf = &mut buf[..bytes_to_copy];

            let offset = (len - bytes_left) as u32;
            src.read(offset, buf)?;
            dest.program(offset, buf)?;

            bytes_left -= bytes_to_copy;
        }
        dest.flush()?;
        Ok(())
    }

    /// Extracts the Platform ID from this Manifest, allocating it onto the provided
    /// arena. Returns `None` if the Platform ID is missing.
    ///
    /// This function will also verify the hash of the Platform ID, if one is
    /// present.
    fn platform_id(
        &self,
        hasher: &mut dyn hash::Engine,
        arena: &'f dyn Arena,
    ) -> Result<Option<PlatformId<'_, 'f, M::Manifest>>, Error> {
        let entry =
            match self.container().toc().singleton(ElementType::PlatformId) {
                Some(x) => x,
                None => return Ok(None),
            };

        #[derive(Clone, Copy, FromBytes, AsBytes)]
        #[repr(C)]
        struct Header {
            len: u8,
            _unused: [u8; 3],
        }
        let (header, rest) = entry.read_with_header::<Header, P>(
            self.container().flash(),
            arena,
            hasher,
        )?;

        let id = rest.get(..header.len as usize).ok_or(Error::TooShort {
            toc_index: entry.index(),
        })?;

        Ok(Some(PlatformId { entry, id }))
    }
}
