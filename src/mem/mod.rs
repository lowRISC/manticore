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
/// This function will always return a value greater than or equal to `addr`.
/// This invariant is always maintained, even if it would cause an unaligned
/// value to be returned.
#[inline]
pub(in crate) fn align_to(addr: usize, align: usize) -> usize {
    let mask = align.wrapping_sub(1);
    let (addr, overflow) = addr.overflowing_add(mask);
    if overflow {
        return usize::MAX;
    }
    addr & !mask
}

/// Computes how far `addr` is from having `align` alignment; that is,
/// how many bytes must `addr` be incremented by to be aligned.
///
/// `align` must be a power of two; otherwise, the returned value
/// will be well-defined but unspecified.
///
/// There is no guarantee that `addr + misalign(addr, n)` will not overflow.
#[inline]
pub(in crate) fn misalign_of(addr: usize, align: usize) -> usize {
    let mask = align.wrapping_sub(1);
    align - (addr & mask)
}
