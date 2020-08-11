// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A reimplementation of [`std::borrow::Cow`] that disables the [`Owned`]
//! variant when `std` is unavailable.
//!
//! See [`Cow`].
//!
//! [`std::borrow::Cow`]: https://doc.rust-lang.org/std/borrow/enum.Cow.html
//! [`Owned`]: https://doc.rust-lang.org/std/borrow/enum.Cow.html#variant.Owned
//! [`Cow`]: struct.Cow.html

/// A clone-on-write smart pointer, usable even when allocation is unavailable.
///
/// This is a type alias for [`std::borrow::Cow`], which gets replaced by a
/// version lacking the `Owned` variant when the `inject-alloc` feature is
/// disabled.
///
/// When `std` is disabled, any APIs of [`std::borrow::Cow`] that would require
/// allocation are unavailable.
///
/// [`std::borrow::Cow`]: https://doc.rust-lang.org/std/borrow/enum.Cow.html
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
///
/// [`std::borrow::Cow`]: https://doc.rust-lang.org/std/borrow/enum.Cow.html
#[cfg(feature = "inject-alloc")]
pub type Cow<'a, B> = std::borrow::Cow<'a, B>;
