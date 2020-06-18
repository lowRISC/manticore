// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Variant of `ref_wrapper` when `arbitrary-derive` is enabled.

use std::borrow::{Cow, ToOwned};
use std::fmt;
use std::fmt::Debug;
use std::ops::Deref;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;

/// A wrapped shared reference type.
///
/// This type exists to make fuzzing easier. It is not possible to implement
/// [`arbitrary::Arbitrary`] on types which contain slice references. When
/// the `arbitrary-derive` Cargo feature is enabled, this type will, rather
/// than wrap a `&'a T`, wrap a `Cow<'a, T>`. This ensures that code that does
/// not need to use allocation does not behave as though it does, to ensure
/// fuzzing fidelity.
#[derive(PartialEq, Eq)]
pub struct Ref<'a, T: ?Sized + ToOwned> {
    inner: Cow<'a, T>,
}

impl<T: ?Sized + ToOwned> Debug for Ref<'_, T>
where
    T: Debug,
    T::Owned: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Ref").field("inner", &self.inner).finish()
    }
}

impl<'a, T: ?Sized + ToOwned> Ref<'a, T> {
    /// Create a new `Ref` that wraps `r`.
    pub fn new(r: &'a T) -> Self {
        Self {
            inner: Cow::Borrowed(r),
        }
    }

    /// Create a new `Ref` that is, internally, a `Cow`.
    pub fn cow(cow: Cow<'a, T>) -> Self {
        Self { inner: cow }
    }

    /// Consume this `Ref`, producing the `Cow` inside.
    pub fn into_inner(self) -> Cow<'a, T> {
        self.inner
    }
}

impl<T: ?Sized + ToOwned> Clone for Ref<'_, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: ?Sized + ToOwned> Deref for Ref<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &*self.inner
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

impl<T: ?Sized + ToOwned> Arbitrary for Ref<'static, T>
where
    Cow<'static, T>: Arbitrary,
{
    fn arbitrary(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Self> {
        Arbitrary::arbitrary(u).map(Self::cow)
    }
    fn arbitrary_take_rest(
        u: arbitrary::Unstructured,
    ) -> arbitrary::Result<Self> {
        Arbitrary::arbitrary_take_rest(u).map(Self::cow)
    }
    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        Cow::<'static, T>::size_hint(depth)
    }
    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new(self.inner.shrink().map(Self::cow))
    }
}
