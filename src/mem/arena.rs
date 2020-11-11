// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! General memory manipulation utilities, such as arenas.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::marker::PhantomData;
use core::mem;
use core::ptr::NonNull;
use core::slice;

use static_assertions::assert_obj_safe;

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;

use crate::mem::align_to;
use crate::mem::stride_of;

/// An error indicating that an [`Arena`] has run out of allocatable
/// memory or that memory that is more aligned than is supported
/// was requested.
///
/// [`Arena`]: trait.Arena.html
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutOfMemory;

/// Represents a re-usable allocation arena.
///
/// An arena can be used to dynamically allocate temporary byte buffers. The
/// `reset()` method can be used to reset the arena to its unallocated state,
/// once all allocated buffers have been rendered unreachable.
///
/// See [`BumpArena`] for an illustration of how the borrow checker is used to
/// do this safely.
///
/// # Safety
///
/// `alloc_aligned()` is required to return memory with certain size and
/// alignment guarantees. While it itself is a safe function, unsafe code
/// is permitted to rely on these guarantees.
///
/// [`BumpArena`]: struct.BumpArena.html
pub unsafe trait Arena {
    /// Allocates `len` bytes of `align`-aligned memory from this arena.
    ///
    /// This is a low-level function: prefer instead to use the helpers defined
    /// in [`ArenaExt`].
    ///
    /// This function may be called multiple times, and the returned slices
    /// will be disjoint.
    ///
    /// After reset is called, this function is permited to return
    /// previously-allocated memory gain, in a way that is visible to Rust.
    /// As such, "poisoned bits", such as the padding bits of Rust structs,
    /// should never be written to memory returned by this function.
    ///
    /// Calling `alloc(0, 1)` must never fail. Note that there is no
    /// requirement that calling `alloc(0, n)` will not return a subslice
    /// of previously returned memory.
    ///
    /// # Panics
    ///
    /// This function will panic if `align` is not a power of two.
    ///
    /// This function is permitted to panic under catastrophic failure
    /// conditions, such as completely running out of program memory.
    /// Implementations must advertize whether they panic.
    ///
    /// [`ArenaExt`]: trait.ArenaExt.html
    fn alloc_aligned(
        &self,
        len: usize,
        align: usize,
    ) -> Result<&mut [u8], OutOfMemory>;

    /// Resets this arena, essentially freeing all memory that was given out
    /// and allowing it to be allocated once more.
    ///
    /// Calling this function requires that all slices that were given out by
    /// this arena are unreachable. Hence, this function must take `self` by
    /// unique reference: this ensures that no one else is holding references
    /// to the memory inside.
    ///
    /// This function need not actually do anything. It is merely required that
    /// the following behavior holds:
    /// ```
    /// # use manticore::mem::*;
    /// # let mut data = [0; 128];
    /// # let mut arena = BumpArena::new(&mut data);
    /// // If the first alloc succeeds (regardless of the value of `len`), then
    /// // the subsequent alloc after resetting the arena must also succeed.
    /// assert!(arena.alloc_aligned(64, 1).is_ok());
    /// arena.reset();
    /// assert!(arena.alloc_aligned(64, 1).is_ok());
    /// ```
    fn reset(&mut self);
}

assert_obj_safe!(Arena);

/// Convenience functions for arenas, exposed as a trait.
///
/// Note that this trait is implemened for `&impl Arena`, which is the reason
/// for the slightly odd signature.
pub trait ArenaExt<'arena> {
    /// Allocates a value of type `T`.
    ///
    /// Because of the `reset()` function, it needs to be safe to transmute
    /// `T` back into bytes. As such, There is an additional `AsBytes` bound.
    /// To avoid having to mess around with destructors, we additionally
    /// require a `Copy` bound, though this may eventually be removed.
    ///
    /// # Panics
    ///
    /// This function is permitted to panic under catastrophic failure
    /// conditions, such as completely running out of program memory.
    /// Implementations must advertize whether they panic.
    fn alloc<T>(self) -> Result<&'arena mut T, OutOfMemory>
    where
        T: AsBytes + FromBytes + Copy;

    /// Allocates a slice with `n` elements.
    ///
    /// Because of the `reset()` function, it needs to be safe to transmute
    /// `T` back into bytes. As such, There is an additional `AsBytes` bound.
    /// To avoid having to mess around with destructors, we additionally
    /// require a `Copy` bound, though this may eventually be removed.
    ///
    /// # Panics
    ///
    /// This function is permitted to panic under catastrophic failure
    /// conditions, such as completely running out of program memory.
    /// Implementations must advertize whether they panic.
    fn alloc_slice<T>(self, n: usize) -> Result<&'arena mut [T], OutOfMemory>
    where
        T: AsBytes + FromBytes + Copy;
}

impl<'arena, A: Arena + ?Sized> ArenaExt<'arena> for &'arena A {
    fn alloc<T: AsBytes + FromBytes + Copy>(
        self,
    ) -> Result<&'arena mut T, OutOfMemory> {
        let bytes =
            self.alloc_aligned(mem::size_of::<T>(), mem::align_of::<T>())?;

        let lv = LayoutVerified::new(bytes)
            .expect("alloc_aligned() implemented incorrectly");
        Ok(lv.into_mut())
    }

    fn alloc_slice<T: AsBytes + FromBytes + Copy>(
        self,
        n: usize,
    ) -> Result<&'arena mut [T], OutOfMemory> {
        let bytes_requested =
            stride_of::<T>().checked_mul(n).ok_or(OutOfMemory)?;
        let bytes =
            self.alloc_aligned(bytes_requested, mem::align_of::<T>())?;

        let lv = LayoutVerified::new_slice(bytes)
            .expect("alloc_aligned() implemented incorrectly");
        Ok(lv.into_mut_slice())
    }
}

/// A bump-allocating [`Arena`] that is backed by a byte slice.
///
/// [`Arena`]: trait.Arena.html
///
/// # Examples
/// ```
/// # use manticore::mem::*;
/// let mut data = [0; 128];
/// let mut arena = BumpArena::new(&mut data);
///
/// let buf1 = arena.alloc::<[u8; 64]>()?;
/// let buf2 = arena.alloc_slice::<u8>(64)?;
/// assert_eq!(buf1.len(), 64);
/// assert!(arena.alloc_slice::<u8>(1).is_err());
///
/// arena.reset();
/// let buf3 = arena.alloc_slice::<u8>(64)?;
/// assert_eq!(buf3.len(), 64);
/// # Ok::<(), OutOfMemory>(())
/// ```
///
/// Note that `BumpArena`'s interface protects callers from mistakedly
/// resetting it while previously-allocated memory remains reachable. For
/// example:
/// ```compile_fail
/// # use manticore::mem::*;
/// let mut data = [0; 128];
/// let mut arena = BumpArena::new(&mut data);
///
/// let buf = arena.alloc_slice::<u8>(64)?;
/// arena.reset();
/// buf[0] = 42;  // Does not compile!
/// # Ok::<(), OutOfMemory>(())
/// ```
///
/// # Panics
///
/// `BumpArena::alloc_aligned()` will never panic.
pub struct BumpArena<'arena> {
    // Even though we do not store `slice`, the lifetime trapped in
    // `lifetime_phantom` ensures that the slice is unaccessible until
    // `self` goes out of scope.
    lifetime_phantom: PhantomData<&'arena mut ()>,
    // Invariant: this pointer points to an allocation, with lifetime 'arena,
    // of `buf_len` bytes at all times. In other words, it points to the first
    // byte of the buffer it was constructed from.
    buf_ptr: NonNull<u8>,
    buf_len: usize,
    // Invariant: cursor <= buf_len. This invariant is assumed when performing
    // unsafe operations.
    cursor: Cell<usize>,
}

impl<'arena> BumpArena<'arena> {
    /// Create a new `BumpArena` by taking ownership of `slice`.
    pub fn new(slice: &'arena mut [u8]) -> Self {
        // There is no way we could ever allocate this much memory. But we
        // include this assertion just in case.
        assert!(slice.len() < isize::MAX as usize);

        Self {
            lifetime_phantom: PhantomData,
            buf_ptr: NonNull::new(slice.as_mut_ptr())
                .expect("slice pointer can never be null"),
            buf_len: slice.len(),
            cursor: Cell::new(0),
        }
    }

    /// Allocates unaligned memory of the given length, moving the cursor
    /// forward as necessary.
    fn alloc_raw(&self, len: usize) -> Result<&mut [u8], OutOfMemory> {
        if len == 0 {
            return Ok(&mut []);
        }
        let cursor = self.cursor.get();
        let proposed_cursor = len.checked_add(cursor).ok_or(OutOfMemory)?;
        if proposed_cursor > self.buf_len {
            return Err(OutOfMemory);
        }

        self.cursor.set(proposed_cursor);
        // At this point, it is not possible for following calls to access
        // the range buf_ptr[cursor..proposed_cursor]. Moreover, the invariants
        // of BumpArena ensure that buf_ptr + cursor must land inside (or one
        // past) the allocation. Hence, the pointer arithmetic that follows is
        // safe, as is the cast to isize.
        let slice = unsafe {
            // SAFE: buf_len >= cursor, and buf_len < isize::MAX; therefore,
            // this cast always produces a positive offset.
            let offset_ptr = self.buf_ptr.as_ptr().add(cursor);
            // SAFE: buf_ptr[cursor..proposed_cursor] is initialized.
            slice::from_raw_parts_mut(offset_ptr, len)
        };

        Ok(slice)
    }

    /// Aligns the internal buffer to the given alignment.
    ///
    /// # Panics
    ///
    /// `align` must be a power of two.
    fn align_to(&self, align: usize) -> Result<(), OutOfMemory> {
        assert!(align.is_power_of_two());

        // SAFE: see the safety notes in alloc_raw().
        let current_addr =
            unsafe { self.buf_ptr.as_ptr().add(self.cursor.get()) as usize };
        let misalignment = align_to(current_addr, align) - current_addr;

        self.alloc_raw(misalignment)?;
        Ok(())
    }
}

unsafe impl<'arena> Arena for BumpArena<'arena> {
    fn alloc_aligned(
        &self,
        len: usize,
        align: usize,
    ) -> Result<&mut [u8], OutOfMemory> {
        if len == 0 {
            assert!(align.is_power_of_two());

            // For length zero, we always just return the base address alligned
            // to the alignment requirement, if that would land inside the
            // slice in the first place.
            let base_addr = self.buf_ptr.as_ptr() as usize;
            let aligned = align_to(base_addr, align);
            let misalignment = aligned - base_addr;
            if misalignment >= self.buf_len {
                return Err(OutOfMemory);
            }

            // SAFE: aligned is in-bounds, and zero-length slices have no
            // aliasing restrictions.
            let slice =
                unsafe { slice::from_raw_parts_mut(aligned as *mut u8, 0) };

            return Ok(slice);
        }

        self.align_to(align)?;
        self.alloc_raw(len)
    }

    // NOTE: because this function takes `self` by unique reference, no mutable
    // slices returned by `alloc()` could have survied, since that would require
    // us to hold a reference to `self`.
    //
    // Thus, followup calls to alloc cannot create aliases, since there are no
    // outstanding poitners to alias.
    fn reset(&mut self) {
        self.cursor.set(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn complex_alignments() {
        let mut data = [0; 128];
        let arena = BumpArena::new(&mut data);

        let buf = arena.alloc_aligned(1, 1).unwrap();
        assert_eq!(buf.len(), 1);

        let buf = arena.alloc_aligned(1, 4).unwrap();
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.as_ptr() as usize % 4, 0);

        let buf = arena.alloc_aligned(0, 4).unwrap();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_ptr() as usize % 4, 0);
    }
}
