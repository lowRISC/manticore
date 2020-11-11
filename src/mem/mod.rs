// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! General memory manipulation utilities, such as arenas.

// TODO: Make this a module people need to access directly.
mod arena;
pub use arena::*;

pub mod cow;

/// Aligns the given address to the alignment for the given type.
///
/// `align` must be a power of two; otherwise, the returned value
/// will be well-defined but unspecified.
///
/// This function will always return a value greather than or equal to `addr`.
#[inline]
pub(in crate) fn align_to(addr: usize, align: usize) -> usize {
    let mask = align.saturating_sub(1);
    let (addr, overflow) = addr.overflowing_add(mask);
    if overflow {
        return usize::MAX;
    }
    addr & !mask
}

/// Computes the stride of `T`, that is, its size rounded up to its alignment.
#[inline]
pub(in crate) fn stride_of<T>() -> usize {
    align_to(core::mem::size_of::<T>(), core::mem::align_of::<T>())
}
