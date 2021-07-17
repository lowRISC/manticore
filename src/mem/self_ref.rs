// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Self-referential helpers.

#![allow(unsafe_code)]

use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::mem::Arena;
use crate::mem::OutOfMemory;

/// A mutable reference that can be "reversibly mapped".
///
/// A `MapMut` holds a mutable reference to a value of type `Base`; this
/// reference can be consumed to create a value of type `Derived`.
///
/// An arena may also be included; this arena can be used to construct
/// the mapped value, and it will be reset whenever the value is
/// "unmapped".
#[derive(Debug)]
pub struct MapMut<'a, Base, Derived, A: Arena = OutOfMemory> {
    // Invariant: if `derived` is None, `base` can safely be dereferenced
    // without violating aliasing.
    base: NonNull<Base>,
    arena: NonNull<A>,
    derived: Option<Derived>,
    _ph: PhantomData<&'a mut (Base, A)>,
}

impl<'a, B, D> MapMut<'a, B, D> {
    /// Create a new `MapMut` wrapping `base`.
    pub fn new(base: &'a mut B) -> Self {
        Self::with_arena(base, OutOfMemory::static_mut())
    }
}

impl<'a, B, D, A: Arena> MapMut<'a, B, D, A> {
    /// Create a new `MapMut` wrapping `base` with the given `arena`.
    pub fn with_arena(base: &'a mut B, arena: &'a mut A) -> Self {
        Self {
            base: NonNull::from(base),
            arena: NonNull::from(arena),
            derived: None,
            _ph: PhantomData,
        }
    }

    /// Returns a reference to the mapped value.
    ///
    /// If the value has not currently been mapped, a reference to the base
    /// type is returned in an `Err`, instead.
    pub fn mapped(&self) -> Result<&D, &B> {
        match &self.derived {
            Some(d) => Ok(d),
            // SAFETY: when `derived` is `None`, this reference is unique.
            None => unsafe { Err(self.base.as_ref()) },
        }
    }

    /// Returns a mutable reference to the mapped value.
    ///
    /// If the value has not currently been mapped, a reference to the base
    /// type is returned in an `Err`, instead.
    pub fn mapped_mut(&mut self) -> Result<&mut D, &mut B> {
        match &mut self.derived {
            Some(d) => Ok(d),
            // SAFETY: when `derived` is `None`, this reference is unique.
            None => unsafe { Err(self.base.as_mut()) },
        }
    }

    /// Maps the wrapped base value using `f`, returning a reference to the
    /// newly mapped value.
    ///
    /// Unlike other functions on this type, `f` receives a reference by
    /// the absolute lifetime `'a`, allowing the type `D` to depend on it.
    pub fn map(&mut self, f: impl FnOnce(&'a mut B, &'a mut A) -> D) -> &mut D {
        // We could do .unwrap(), but that would probably emit an extra bounds
        // check...
        match self.try_map::<core::convert::Infallible, _>(|b, a| Ok(f(b, a))) {
            Ok(x) => x,
            Err(e) => match e {}, // My kingdom for a never-type.
        }
    }

    /// Maps the wrapped base value using `f`, returning a reference to the
    /// newly mapped value. The mapping function is permitted to fail.
    ///
    /// Unlike other functions on this type, `f` receives a reference by
    /// the absolute lifetime `'a`, allowing the type `D` to depend on it.
    pub fn try_map<E, F>(&mut self, f: F) -> Result<&mut D, E>
    where
        F: FnOnce(&'a mut B, &'a mut A) -> Result<D, E>,
    {
        // SAFETY: Ensure that any references to `self.base` are destroyed
        // before we convert it to a reference.
        self.unmap();
        self.derived = Some(f(
            // NOTE: We cannot use .as_mut(), since that would use the
            // lifetime of &mut self; we want to manually dereference it
            // to make the lifetime "unbound"; this is fine, because the
            // lifetime it will pick is `'a`.
            unsafe { &mut *self.base.as_ptr() },
            unsafe { &mut *self.arena.as_ptr() },
        )?);
        Ok(self.derived.as_mut().unwrap())
    }

    /// Destroys the derived value, if it exists, and returns a reference to
    /// the base value.
    pub fn unmap(&mut self) -> &mut B {
        // SAFETY: Ensure that any references to `self.base` are destroyed
        // before we convert it to a reference.
        self.derived = None;
        unsafe {
            self.arena.as_mut().reset();
            self.base.as_mut()
        }
    }
}

impl<B, D, A: Arena> Drop for MapMut<'_, B, D, A> {
    fn drop(&mut self) {
        // Trigger an arena reset.
        self.unmap();
        // No need to destroy the base or the arena, since we don't actually
        // own them.
    }
}
