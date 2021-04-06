// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use core::marker::PhantomData;

use crate::crypto::rsa;
use crate::crypto::sha256;
use crate::hardware::flash::Flash;
use crate::manifest::provenance;
use crate::manifest::Container;
use crate::manifest::Error;
use crate::manifest::Parse;
use crate::manifest::ValidationTime;
use crate::mem::Arena;
use crate::mem::MapMut;

/// A manifest manager, responsible for handling loading and updates of a
/// [`Manifest`] in flash.
///
/// A `Manager` tracks the flash location that is the long-term storage for a
/// manifest, as well as the resource that the Manager guards, if any. For
/// example, this would be the remote flash storage (containing platform
/// firmware) that a PFM describes.
pub struct Manager<'f, Manifest, Flash, Arena, Provenance = provenance::Signed>
where
    Manifest: Parse<'f, Flash, Provenance>,
    Arena: crate::mem::Arena,
{
    manifest: MapMut<
        'f,
        Flash,
        <Manifest as Parse<'f, Flash, Provenance>>::Parsed,
        Arena,
    >,
    guarded: Manifest::Guarded,
    _ph: PhantomData<fn() -> Provenance>,
}

impl<'f, M, F, A, P> Manager<'f, M, F, A, P>
where
    A: Arena,
    M: Parse<'f, F, P>,
{
    /// Creates a new `Manager` to track a manifest at `flash`.
    ///
    /// `arena` is used as auxiliary storage for parsing the manifest out of
    /// `flash`, as necessary; `guarded` is the resource that the [`Manifest`]
    /// type guards.
    pub fn new(
        flash: &'f mut F,
        arena: &'f mut A,
        guarded: M::Guarded,
    ) -> Self {
        Self {
            manifest: MapMut::with_arena(flash, arena),
            guarded,
            _ph: PhantomData,
        }
    }

    /// Returns a reference to the cached parsed manifest value.
    ///
    /// This function will return `None` until either [`Manifest::init()`]
    /// or [`Manifest::activate()`] has been called.
    pub fn manifest(&self) -> Option<&M::Parsed> {
        self.manifest.mapped().ok()
    }

    /// Explicitly runs the managed manifest's validation routine, as if it were
    /// being run at `when` time.
    ///
    /// This function returns `Ok(())` without doing anything if not manifest
    /// has been parsed yet.
    pub fn validate(&self, when: ValidationTime) -> Result<(), Error> {
        let manifest = match self.manifest() {
            Some(m) => m,
            None => return Ok(()),
        };
        M::validate(manifest, when, &self.guarded)
    }
}

impl<'f, M, F, A> Manager<'f, M, F, A, provenance::Signed>
where
    M: Parse<'f, F, provenance::Signed>,
    F: Flash,
    A: Arena,
{
    /// Triggers startup initialization for this `Manager`.
    ///
    /// In effect, this function parses and verifies the manifest in the flash
    /// region that backs this `Manager`, and then runs [`Parse::validate()`]
    /// on the resulting structure.
    ///
    /// The `sha`, `rsa`, and `verify_arena` arguments are as those in
    /// [`Container::parse_and_verify()`].
    pub fn startup(
        &mut self,
        sha: &impl sha256::Builder,
        rsa: &mut impl rsa::Engine,
        verify_arena: &impl Arena,
    ) -> Result<&M::Parsed, Error> {
        let manifest = self.manifest.try_map(|flash, arena| {
            let container = Container::parse_and_verify(
                flash,
                sha,
                rsa,
                arena,
                verify_arena,
            )?;
            M::parse(container)
        })?;
        M::validate(manifest, ValidationTime::Startup, &self.guarded)?;
        Ok(manifest)
    }

    /// Activates a pending manifest located at `new_manifest`.
    ///
    /// This function parses a manifest out of `new_manifest`, runs
    /// [`Parse::validate()`] on it, and then writes it to the backing
    /// flash for this `Manager`. It then re-parses and re-verifies the
    /// newly activated manifest.
    ///
    /// This function can also be used to provision a new manifest without
    /// looking at the existing manifest in flash; it is sufficient that the
    /// new manifest be appropriately signed and valid (per
    /// [`Parse::validate()`]).
    ///
    /// The `sha`, `rsa`, `toc_arena` and `verify_arena` arguments are as those
    /// in [`Container::parse_and_verify()`].
    pub fn activate<'f2, F2: Flash>(
        &mut self,
        new_manifest: &'f2 F2,
        sha: &impl sha256::Builder,
        rsa: &mut impl rsa::Engine,
        toc_arena: &'f2 impl Arena,
        verify_arena: &impl Arena,
    ) -> Result<&<M as Parse<'f, F, provenance::Signed>>::Parsed, Error>
    where
        M: Parse<'f2, F2, provenance::Signed>,
    {
        // First, parse and verify the signature of the new manifest.
        let container = Container::parse_and_verify(
            new_manifest,
            sha,
            rsa,
            toc_arena,
            verify_arena,
        )?;
        let new_parsed = M::parse(container)?;

        // Then, validate that it the guarded resource is consistent with this
        // manifest type.
        <M as Parse<'f2, F2, _>>::validate(
            &new_parsed,
            ValidationTime::Activation,
            &self.guarded,
        )?;

        // Finally copy it into its new home and replace `self.manifest` with
        // it.
        <M as Parse<'f2, F2, _>>::copy_to(&new_parsed, self.manifest.unmap())?;
        let manifest = self.manifest.try_map(|flash, arena| {
            let container = Container::parse_and_verify(
                flash,
                sha,
                rsa,
                arena,
                verify_arena,
            )?;
            M::parse(container)
        })?;

        Ok(manifest)
    }
}
