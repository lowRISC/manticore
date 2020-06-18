// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Compile-time replaceable reference wrapper.
//!
//! Note that when `arbitrary-derive` is enabled, this file is replaced by
//! `ref_wrapper_cow.rs`.

use core::ops::Deref;

/// Stand-in type for `std::borrow::ToOwned`.
#[doc(hidden)]
pub trait ToOwned {}

impl<T> ToOwned for T where T: Clone {}
impl ToOwned for str {}
impl<T> ToOwned for [T] {}

/// A wrapped shared reference type.
///
/// This type exists to make fuzzing easier. It is not possible to implement
/// [`arbitrary::Arbitrary`] on types which contain slice references. When
/// the `arbitrary-derive` Cargo feature is enabled, this type will, rather
/// than wrap a `&'a T`, wrap a `Cow<'a, T>`. This ensures that code that does
/// not need to use allocation does not behave as though it does, to ensure
/// fuzzing fidelity.
#[derive(Debug, PartialEq, Eq)]
pub struct Ref<'a, T: ?Sized + ToOwned> {
    inner: &'a T,
}

impl<'a, T: ?Sized + ToOwned> Ref<'a, T> {
    /// Create a new `Ref` that wraps `r`.
    pub fn new(r: &'a T) -> Self {
        Self { inner: r }
    }
}

impl<T: ?Sized + ToOwned> Clone for Ref<'_, T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner }
    }
}

impl<T: ?Sized + ToOwned> Deref for Ref<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.inner
    }
}

impl<T: ?Sized + ToOwned> AsRef<T> for Ref<'_, T> {
    fn as_ref(&self) -> &T {
        &*self
    }
}

impl<'a, T: ?Sized + ToOwned> From<&'a T> for Ref<'a, T> {
    fn from(r: &'a T) -> Self {
        Self::new(r)
    }
}
