//! General memory manipulation utilities, such as arenas.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::slice;

use static_assertions::assert_obj_safe;

/// An error indicating that an [`Arena`] has run out of allocatable
/// memory.
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
/// [`BumpArena`]: struct.BumpArena.html
pub trait Arena {
    /// Allocate `len` bytes of memory from this arena.
    ///
    /// This function may be called multiple times, and the returned slices
    /// will be disjoint.
    ///
    /// After reset is called, this function is permited to return
    /// previously-allocated memory gain, in a way that is visible to Rust.
    /// As such, "poisoned bits", such as the padding bits of Rust structs,
    /// should never be written to memory returned by this function.
    ///
    /// Calling `alloc(0)` must never fail.
    ///
    /// # Panics
    ///
    /// This function is permitted to panic under catastrophic failure
    /// conditions, such as completely running out of program memory.
    /// Implementations must advertize whether they panic.
    fn alloc(&self, len: usize) -> Result<&mut [u8], OutOfMemory>;

    /// Resets this arena, essentially freeing all memory that was given out
    /// and allowing it to be allocated once more.
    ///
    /// Calling this function requires that all slices that were given out by
    /// `alloc()` are unreachable. Hence, this function must take `self` by
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
    /// assert!(arena.alloc(64).is_ok());
    /// arena.reset();
    /// assert!(arena.alloc(64).is_ok());
    /// ```
    fn reset(&mut self);
}

assert_obj_safe!(Arena);

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
/// let buf1 = arena.alloc(64)?;
/// let buf2 = arena.alloc(64)?;
/// assert_eq!(buf1.len(), 64);
/// assert!(arena.alloc(1).is_err());
///
/// arena.reset();
/// let buf3 = arena.alloc(64)?;
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
/// let buf = arena.alloc(64)?;
/// arena.reset();
/// buf[0] = 42;  // Does not compile!
/// # Ok::<(), OutOfMemory>(())
/// ```
///
/// # Panics
///
/// `BumpArena::alloc()` will never panic.
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
}

impl<'arena> Arena for BumpArena<'arena> {
    fn alloc(&self, len: usize) -> Result<&mut [u8], OutOfMemory> {
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
            let offset_ptr = self.buf_ptr.as_ptr().offset(cursor as isize);
            // SAFE: buf_ptr[cursor..proposed_cursor] is initialized.
            slice::from_raw_parts_mut(offset_ptr, len)
        };

        Ok(slice)
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
