// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A reimplementation of [`std::borrow::Cow`] that disables the [`Owned`]
//! variant when `std` is unavailable.
//!
//! See [`Cow`].

#[cfg(doc)]
use std::borrow::Cow::Owned;

/// A clone-on-write smart pointer, usable even when allocation is unavailable.
///
/// This is a type alias for [`std::borrow::Cow`], which gets replaced by a
/// version lacking the `Owned` variant when the `inject-alloc` feature is
/// disabled.
///
/// When `std` is disabled, any APIs of [`std::borrow::Cow`] that would require
/// allocation are unavailable.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg(not(feature = "inject-alloc"))]
pub enum Cow<'a, B>
where
    B: 'a + ?Sized,
{
    /// The sole variant; when `inject-alloc` is disabled, only the borrowed form
    /// is available.
    Borrowed(&'a B),
}

#[cfg(not(feature = "inject-alloc"))]
impl<'a, B> core::ops::Deref for Cow<'a, B>
where
    B: 'a + ?Sized,
{
    type Target = B;

    #[inline(always)]
    fn deref(&self) -> &B {
        match self {
            Self::Borrowed(x) => x,
        }
    }
}

/// A clone-on-write smart pointer, usable even when allocation is unavailable.
///
/// This is a type alias for [`std::borrow::Cow`], which gets replaced by a
/// version lacking the `Owned` variant when the `inject-alloc` feature is
/// disabled.
///
/// When `std` is disabled, any APIs of [`std::borrow::Cow`] that would require
/// allocation are unavailable.
#[cfg(feature = "inject-alloc")]
pub type Cow<'a, B> = std::borrow::Cow<'a, B>;
