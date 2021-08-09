// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! General memory manipulation utilities, such as arenas.

#![allow(unsafe_code)]

use core::alloc::Layout;
use core::cell::Cell;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::slice;

use static_assertions::assert_obj_safe;

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;

use crate::mem::align_to;

#[cfg(doc)]
use core::mem;

/// An error indicating that an [`Arena`] has run out of allocatable
/// memory or that memory that is more aligned than is supported
/// was requested.
///
/// Additionally, `OutOfMemory` implements [`Arena`] itself, acting as the
/// "trivial" no-memory-was-provided arena. This is particularly useful for
/// when it is known that no memory will ever be allocated on the arena.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutOfMemory;

unsafe impl Arena for OutOfMemory {
    fn alloc_raw(&self, layout: Layout) -> Result<&mut [u8], OutOfMemory> {
        if layout.size() == 0 {
            // SAFE: zero-length slices have no restrictions on the pointer
            // beyond non-null-ness and well-aligned-ness, so we materialize
            // one out of thin air.
            //
            // NonNull::dangling() is optimal, but that requires having a
            // concrete type. See the note on zero-length slices in
            // https://doc.rust-lang.org/std/slice/fn.from_raw_parts_mut.html
            Ok(unsafe {
                slice::from_raw_parts_mut(layout.align() as *mut u8, 0)
            })
        } else {
            Err(*self)
        }
    }

    fn reset(&mut self) {}
}

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
/// [`Arena::alloc_raw()`] is required to return memory with certain size and
/// alignment guarantees. While it itself is a safe function, unsafe code
/// is permitted to rely on these guarantees.
pub unsafe trait Arena {
    /// Allocates memory with the given `layout`.
    ///
    /// This is a low-level function: prefer instead to use the helpers defined
    /// in [`ArenaExt`].
    ///
    /// This function may be called multiple times, and the returned slices
    /// will be disjoint.
    ///
    /// After reset is called, this function is permitted to return
    /// previously-allocated memory gain, in a way that is visible to Rust.
    /// As such, "poisoned bits", such as the padding bits of Rust structs,
    /// should never be written to memory returned by this function.
    ///
    /// Calling with a zero-sized, unaligned layout (e.g.,
    /// `Layout::new::<()>()`) must never fail. Note that there is no
    /// note that there is no requirement that calling with a zero-sized
    /// layout will return unique addresses.
    ///
    /// # Panics
    ///
    /// This function will panic if `align` is not a power of two.
    ///
    /// This function is permitted to panic under catastrophic failure
    /// conditions, such as completely running out of program memory.
    /// Implementations must advertise whether they panic.
    fn alloc_raw(&self, layout: Layout) -> Result<&mut [u8], OutOfMemory>;

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
    /// # use core::alloc::Layout;
    /// # let mut arena = BumpArena::new([0; 128]);
    /// // If the first alloc succeeds (regardless of the value of `len`), then
    /// // the subsequent alloc after resetting the arena must also succeed.
    /// assert!(arena.alloc_raw(Layout::new::<[u8; 64]>()).is_ok());
    /// arena.reset();
    /// assert!(arena.alloc_raw(Layout::new::<[u8; 64]>()).is_ok());
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
        let bytes = self.alloc_raw(Layout::new::<T>())?;

        let lv = LayoutVerified::<_, T>::new(bytes)
            .expect("alloc_raw() implemented incorrectly");
        Ok(lv.into_mut())
    }

    fn alloc_slice<T: AsBytes + FromBytes + Copy>(
        self,
        n: usize,
    ) -> Result<&'arena mut [T], OutOfMemory> {
        let bytes =
            self.alloc_raw(Layout::array::<T>(n).map_err(|_| OutOfMemory)?)?;

        let lv = LayoutVerified::<_, [T]>::new_slice(bytes)
            .expect("alloc_raw() implemented incorrectly");
        Ok(lv.into_mut_slice())
    }
}

/// A bump-allocating [`Arena`] that is backed by fixed storage.
///
/// The type parameter is a type that can provide stable byte storage as long
/// as it is not moved, such as a byte array, a byte slice, or even a [`Vec`]!
///
/// # Examples
/// ```
/// # use manticore::mem::*;
/// let mut arena = BumpArena::new([0; 128]);
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
/// let mut arena = BumpArena::new([0; 128]);
///
/// let buf = arena.alloc_slice::<u8>(64)?;
/// arena.reset();
/// buf[0] = 42;  // Does not compile!
/// # Ok::<(), OutOfMemory>(())
/// ```
///
/// # Panics
///
/// `BumpArena::alloc_raw()` will never panic.
#[derive(Default)]
pub struct BumpArena<B: Buf> {
    buf: B::Raw,
    _ph: PhantomData<B>,
    // Invariant: cursor <= buf_len. This invariant is assumed when performing
    // unsafe operations.
    cursor: Cell<usize>,
}

impl<B: Buf> BumpArena<B> {
    /// Create a new `BumpArena` by taking ownership of `buf`.
    pub fn new(buf: B) -> Self {
        let buf = buf.into_raw();

        // There is no way we could ever allocate this much memory. But we
        // include this assertion just in case.
        let (_, len) = unsafe { B::as_slice_from_raw(&buf) };
        assert!(len < isize::MAX as usize);

        Self {
            buf,
            _ph: PhantomData,
            cursor: Cell::new(0),
        }
    }

    fn as_ref(&self) -> BumpArenaRef {
        let (buf_ptr, buf_len) = unsafe { B::as_slice_from_raw(&self.buf) };
        BumpArenaRef {
            buf_ptr,
            buf_len,
            cursor: &self.cursor,
        }
    }
}

impl<B: Buf> Drop for BumpArena<B> {
    fn drop(&mut self) {
        unsafe {
            B::drop(&mut self.buf);
        }
    }
}

/// Wrapper around non-generic state of [`BumpArena`], to help cut down on code
/// size.
#[derive(Copy, Clone)]
struct BumpArenaRef<'arena> {
    buf_ptr: *mut u8,
    buf_len: usize,
    cursor: &'arena Cell<usize>,
}

impl<'arena> BumpArenaRef<'arena> {
    /// Allocates unaligned memory of the given length, moving the cursor
    /// forward as necessary.
    fn alloc_inner(self, len: usize) -> Result<&'arena mut [u8], OutOfMemory> {
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
            let offset_ptr = self.buf_ptr.add(cursor);
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
    fn align_to(self, align: usize) -> Result<(), OutOfMemory> {
        assert!(align.is_power_of_two());

        // SAFE: see the safety notes in alloc_raw().
        let current_addr =
            unsafe { self.buf_ptr.add(self.cursor.get()) as usize };
        let aligned = align_to(current_addr, align);
        if aligned == usize::MAX && align > 1 {
            // We've hit the top of the address space, so we have no hope of
            // allocating aligned memory.
            return Err(OutOfMemory);
        }
        let misalignment = aligned - current_addr;

        self.alloc_inner(misalignment)?;
        Ok(())
    }
}

unsafe impl<B: Buf> Arena for BumpArena<B> {
    fn alloc_raw(&self, layout: Layout) -> Result<&mut [u8], OutOfMemory> {
        if layout.size() == 0 {
            // Forward to OutOfMemory, which will always succeed on zero-length
            // allocations.
            return OutOfMemory.alloc_raw(layout);
        }

        let a = self.as_ref();
        a.align_to(layout.align())?;
        a.alloc_inner(layout.size())
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

/// A type that can serve as a buffer an arena can allocate from.
///
/// # Safety
///
/// This trait is unsafe to implement. In particular, the following
/// must hold:
/// - The return value of [`Buf::into_raw()`] must own exactly the same
///   resources as the value passed into it.
/// - Calling [`Buf::as_slice_from_raw()`] on a [`Buf::Raw`] will always
///   produce the same pointer/length pair as long as the raw storage is not
///   moved. This is weaker than, say, the [`StableDeref`] guarantee.
/// - Both [`Buf::as_slice_from_raw()`] and [`Buf::as_slice()`] produce valid
///   pointer/length pairs (i.e., they could be turned into slices via
///   [`slice::from_raw_parts_mut()`]).
/// - Although [`Self::into_raw()`] has a default implementation, it is only
///   provided to facilitate implementations for `T: !Sized` types. It must be
///   explicitly implemented by all `Sized` implementers.
///
/// [`StableDeref`]: https://docs.rs/stable_deref_trait/1.2.0/stable_deref_trait/trait.StableDeref.html
pub unsafe trait Buf {
    /// A version of `Self` that has been "dismantled" in some way. It still
    /// owns the same resources as `Self`, but is no longer treated as aliasing
    /// with anything. It is a version of `Self` that "lives on", even though
    /// its original form is gone.
    ///
    /// For example, this would be `(*mut T, usize)` for `&mut [T]`, or just
    /// `UnsafeCell<[u8; N]>` for `[u8; N]`. Users of `Buf` should take care
    /// to carry around a [`PhantomData<T>`] corresponding to the dismantled
    /// type.
    ///
    /// The choice of this type should not be considered stable for any
    /// particular type.
    type Raw: Sized;

    /// Converts `self` into a [`Buf::Raw`] that represents it.
    fn into_raw(self) -> Self::Raw
    where
        Self: Sized,
    {
        panic!("Buf::into_raw() not implemented; this is a bug.")
    }

    /// Like [`Buf::as_slice_from_raw()`], but callable on a value of type [`Self`].
    ///
    /// This function mostly exists to facilitate the blanket impl for
    /// `&mut impl Buf`.
    fn as_slice(&mut self) -> (*mut u8, usize);

    /// Drops a [`Self::Raw`] by reconstituting it into a [`Self`].
    ///
    /// # Safety
    ///
    /// This function should only be called once per value produced by
    /// [`Buf::into_raw()`], and not on any other values.
    ///
    /// Before calling this function, you must call [`mem::forget()`] on
    /// the value [`Buf::into_raw()`] was called on.
    unsafe fn drop(#[allow(unused)] raw: &mut Self::Raw) {}

    /// Turns a raw buffer into a raw slice.
    ///
    /// # Safety
    ///
    /// This function should only be called on values produced from
    /// [`Buf::into_raw()`], which have not yet been passed to
    /// [`Buf::drop()`].
    #[allow(clippy::wrong_self_convention)]
    unsafe fn as_slice_from_raw(raw: &Self::Raw) -> (*mut u8, usize);
}

unsafe impl Buf for [u8] {
    type Raw = (*mut u8, usize);

    #[inline]
    unsafe fn as_slice_from_raw(raw: &Self::Raw) -> (*mut u8, usize) {
        *raw
    }

    #[inline]
    fn as_slice(&mut self) -> (*mut u8, usize) {
        (self.as_mut_ptr(), self.len())
    }
}

unsafe impl<const N: usize> Buf for [u8; N] {
    type Raw = UnsafeCell<Self>;

    #[inline]
    fn into_raw(self) -> Self::Raw {
        UnsafeCell::new(self)
    }

    #[inline]
    unsafe fn as_slice_from_raw(raw: &Self::Raw) -> (*mut u8, usize) {
        (raw.get() as *mut u8, N)
    }

    #[inline]
    fn as_slice(&mut self) -> (*mut u8, usize) {
        (self.as_mut_ptr(), N)
    }
}

unsafe impl<B: Buf + ?Sized> Buf for &mut B {
    type Raw = (*mut u8, usize);

    #[inline]
    fn into_raw(self) -> Self::Raw {
        self.as_slice()
    }

    #[inline]
    unsafe fn as_slice_from_raw(raw: &Self::Raw) -> (*mut u8, usize) {
        *raw
    }

    #[inline]
    fn as_slice(&mut self) -> (*mut u8, usize) {
        self.into_raw()
    }
}

#[cfg(feature = "std")]
unsafe impl Buf for Vec<u8> {
    // Ptr, len, cap.
    type Raw = (*mut u8, usize, usize);

    #[inline]
    fn into_raw(mut self) -> Self::Raw {
        let raw = (self.as_mut_ptr(), self.len(), self.capacity());
        core::mem::forget(self);
        raw
    }

    #[inline]
    unsafe fn drop(&mut (ptr, len, cap): &mut Self::Raw) {
        let _ = Vec::from_raw_parts(ptr, len, cap);
    }

    #[inline]
    unsafe fn as_slice_from_raw(
        &(ptr, len, _): &Self::Raw,
    ) -> (*mut u8, usize) {
        (ptr, len)
    }

    #[inline]
    fn as_slice(&mut self) -> (*mut u8, usize) {
        (self.as_mut_ptr(), self.len())
    }
}

#[cfg(feature = "std")]
unsafe impl Buf for Box<[u8]> {
    type Raw = (*mut u8, usize);

    #[inline]
    fn into_raw(mut self) -> Self::Raw {
        let raw = (self.as_mut_ptr(), self.len());
        core::mem::forget(self);
        raw
    }

    #[inline]
    unsafe fn drop(&mut (ptr, len): &mut Self::Raw) {
        let slice = slice::from_raw_parts_mut(ptr, len);
        let _ = Box::from_raw(slice);
    }

    #[inline]
    unsafe fn as_slice_from_raw(raw: &Self::Raw) -> (*mut u8, usize) {
        *raw
    }

    #[inline]
    fn as_slice(&mut self) -> (*mut u8, usize) {
        (self.as_mut_ptr(), self.len())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bump_array() {
        let arena = BumpArena::<[u8; 128]>::new([0; 128]);

        let buf = arena
            .alloc_raw(Layout::from_size_align(1, 1).unwrap())
            .unwrap();
        assert_eq!(buf.len(), 1);

        let buf = arena
            .alloc_raw(Layout::from_size_align(1, 4).unwrap())
            .unwrap();
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.as_ptr() as usize % 4, 0);

        let buf = arena
            .alloc_raw(Layout::from_size_align(0, 4).unwrap())
            .unwrap();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_ptr() as usize % 4, 0);
    }

    #[test]
    fn bump_slice() {
        let mut data = [0; 128];
        let arena = BumpArena::<&mut [u8]>::new(data.as_mut());

        let buf = arena
            .alloc_raw(Layout::from_size_align(1, 1).unwrap())
            .unwrap();
        assert_eq!(buf.len(), 1);

        let buf = arena
            .alloc_raw(Layout::from_size_align(1, 4).unwrap())
            .unwrap();
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.as_ptr() as usize % 4, 0);

        let buf = arena
            .alloc_raw(Layout::from_size_align(0, 4).unwrap())
            .unwrap();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_ptr() as usize % 4, 0);
    }
}
