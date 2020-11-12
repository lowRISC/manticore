// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! External, remote flash abstraction.
//!
//! This crate provides the [`Flash`] (and related) traits, which represent
//! *abstract flash devices*. An abstract flash device is a region of memory
//! that can be transactionally read or written. Such a "device" can range
//! from a simple Rust slice to a remote SPI flash device (or even a subregion of
//! it!).
//!
//! [`Flash`]: trait.Flash.html

#![allow(unsafe_code)]

use core::convert::TryInto;
use core::mem;

use static_assertions::assert_obj_safe;

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::io;
use crate::io::Read as _;
use crate::mem::stride_of;
use crate::mem::Arena;
use crate::mem::OutOfMemory;

/// A [`Flash`] error.
///
/// All of these errors are non-retryable; a [`Flash`] implementation should
/// block until the operation succeeds.
///
/// [`Flash`]: trait.Flash.html
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// Indicates that an operation failed because the requested
    /// operation was outside of the device's address space.
    OutOfRange,

    /// Indicates that the device is locked in some manner and cannot
    /// be affected by the operation.
    Locked,

    /// Indicates that an internal invariant was violated, such as running out
    /// of memory.
    Internal,

    /// Indicates that an unspecified error occured.
    Unspecified,
}

impl From<OutOfMemory> for Error {
    fn from(_: OutOfMemory) -> Error {
        Error::Internal
    }
}

/// Provides access to a flash-like storage device.
///
/// This trait provides abstract operations on a device, as if it were a
/// block of random-access memory. It is the implementation's responsibility
/// to implement these operations efficiently with respect to the underlying
/// device.
///
/// # Safety
///
/// This trait is unsafe due to alignment requirements in `read_direct()`.
pub unsafe trait Flash {
    /// Returns the size, in bytes, of this device.
    fn size(&self) -> Result<u32, Error>;

    /// Attempts to read `out.len()` bytes starting at `offset`.
    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error>;

    /// Attempts to perform a "direct read" of the given `Region`.
    ///
    /// This function provides an optimization opportunity to implementations.
    /// Some implementations, such as [`Ram`], already hold all of their
    /// contents in memory and so can return a reference into themselves;
    /// however, physically external flash may not have such a choice. Thus,
    /// an arena must be passed in to provide for the possiblity of an
    /// allocation requirement.
    ///
    /// This function additionally takes an alignment requirement: it may be
    /// useful to require that the returned memory be aligned. Passing an
    /// alignment greater than `1` may reduce the possibility of avoiding
    /// copies.
    ///
    /// This function is not provided with a default implementation, though
    /// the following should be a sufficient starting point:
    /// ```
    /// # use manticore::mem::*;
    /// # use manticore::hardware::flash::*;
    /// # struct Foo;
    /// # impl Foo {
    /// # fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
    /// #   Ok(())
    /// # }
    /// fn read_direct<'a: 'c, 'b: 'c, 'c>(
    ///     &'a self,
    ///     region: Region,
    ///     arena: &'b dyn Arena,
    ///     align: usize,
    /// ) -> Result<&'c [u8], Error> {
    ///     let mut buf = arena.alloc_aligned(region.len as usize, align)?;
    ///     self.read(region.ptr, &mut buf)?;
    ///     Ok(buf)
    /// }
    /// # }
    /// ```
    /// # Panics
    ///
    /// This function may panic if `align` is not a power of two.
    fn read_direct<'a: 'c, 'b: 'c, 'c>(
        &'a self,
        region: Region,
        arena: &'b dyn Arena,
        align: usize,
    ) -> Result<&'c [u8], Error>;

    /// Attempts to write `out.len()` bytes starting at `offset`.
    ///
    /// Note that this function is not guaranteed to succeed (and be
    /// reflected in the return value of `read`) until `flush()` is called.
    /// This is to permit a `Flash` implementation to buffer writes before
    /// sending them out.
    ///
    /// Implementations are, as an optimization, permitted to assume that
    /// writes will be serial and localized, so as to minimize clearing
    /// operations on flash hardware.
    fn program(&mut self, offset: Ptr, buf: &[u8]) -> Result<(), Error>;

    /// Flushes any pending `program()` operations.
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
assert_obj_safe!(Flash);

unsafe impl<F: Flash> Flash for &F {
    #[inline]
    fn size(&self) -> Result<u32, Error> {
        F::size(self)
    }

    #[inline]
    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
        F::read(self, offset, out)
    }

    #[inline]
    fn read_direct<'a: 'c, 'b: 'c, 'c>(
        &'a self,
        region: Region,
        arena: &'b dyn Arena,
        align: usize,
    ) -> Result<&'c [u8], Error> {
        F::read_direct(self, region, arena, align)
    }

    #[inline]
    fn program(&mut self, _: Ptr, _: &[u8]) -> Result<(), Error> {
        Err(Error::Locked)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        Err(Error::Locked)
    }
}

unsafe impl<F: Flash> Flash for &mut F {
    #[inline]
    fn size(&self) -> Result<u32, Error> {
        F::size(self)
    }

    #[inline]
    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
        F::read(self, offset, out)
    }

    #[inline]
    fn read_direct<'a: 'c, 'b: 'c, 'c>(
        &'a self,
        region: Region,
        arena: &'b dyn Arena,
        align: usize,
    ) -> Result<&'c [u8], Error> {
        F::read_direct(self, region, arena, align)
    }

    #[inline]
    fn program(&mut self, offset: Ptr, buf: &[u8]) -> Result<(), Error> {
        F::program(self, offset, buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        F::flush(self)
    }
}

/// Convenience functions for direct flash reads, exposed as a trait.
///
/// Note that this trait is implemened for `&impl Flash`, which is the reason
/// for the slightly odd signature.
pub trait FlashExt<'flash> {
    /// Reads a value of type `T`.
    ///
    /// See [`ArenaExt::alloc()`](../../mem/arena/trait.ArenaExt.html#tymethod.alloc).
    fn read_object<'b: 'c, 'c, T>(
        self,
        offset: Ptr,
        arena: &'b dyn Arena,
    ) -> Result<&'c T, Error>
    where
        'flash: 'c,
        T: AsBytes + FromBytes + Copy;

    /// Reads a slice of type `[T]`.
    ///
    /// See [`ArenaExt::alloc_slice()`](../../mem/arena/trait.ArenaExt.html#tymethod.alloc_slice).
    fn read_slice<'b: 'c, 'c, T>(
        self,
        offset: Ptr,
        n: usize,
        arena: &'b dyn Arena,
    ) -> Result<&'c [T], Error>
    where
        'flash: 'c,
        T: AsBytes + FromBytes + Copy;
}

impl<'flash, F: Flash> FlashExt<'flash> for &'flash F {
    fn read_object<'b: 'c, 'c, T>(
        self,
        offset: Ptr,
        arena: &'b dyn Arena,
    ) -> Result<&'c T, Error>
    where
        'flash: 'c,
        T: AsBytes + FromBytes + Copy,
    {
        let bytes = self.read_direct(
            Region::new(offset.address, mem::size_of::<T>() as u32),
            arena,
            mem::align_of::<T>(),
        )?;

        let lv = LayoutVerified::<_, T>::new(bytes)
            .expect("alloc_aligned() implemented incorrectly");
        Ok(lv.into_ref())
    }

    fn read_slice<'b: 'c, 'c, T>(
        self,
        offset: Ptr,
        n: usize,
        arena: &'b dyn Arena,
    ) -> Result<&'c [T], Error>
    where
        'flash: 'c,
        T: AsBytes + FromBytes + Copy,
    {
        let bytes_requested =
            stride_of::<T>().checked_mul(n).ok_or(OutOfMemory)?;
        let bytes = self.read_direct(
            Region::new(offset.address, bytes_requested as u32),
            arena,
            mem::align_of::<T>(),
        )?;

        let lv = LayoutVerified::<_, [T]>::new_slice(bytes)
            .expect("alloc_aligned() implemented incorrectly");
        Ok(lv.into_slice())
    }
}

/// Adapter for working with a sub-region of a [`Flash`] type.
///
/// Reads and writes on the device will be constrained to a given [`Region`].
/// This is especially useful for operating on a blob contained within another
/// region of flash.
///
/// There is no requirement that [`Region`] actually overlap with the address
/// space of `F`; the [`Flash`] implementation is still responsible for doing
/// bounds checks, after offsets are bounds-checked within `Region`.
#[derive(Copy, Clone)]
pub struct SubFlash<F>(pub F, pub Region);

impl<F: Flash> SubFlash<F> {
    /// Creates a new `SubFlash` representing the entirety of the given device.
    pub fn full(flash: F) -> Result<Self, Error> {
        let region = Region::new(0, flash.size()?);
        Ok(Self(flash, region))
    }
}

impl<F> SubFlash<F> {
    /// Interprets `region` as a subregion of this `SubFlash`, returning a new
    /// `SubFlash` that represents that region.
    pub fn reslice(self, region: Region) -> Option<Self> {
        if region.len >= self.1.len {
            return None;
        }

        Some(Self(
            self.0,
            Region::new(
                self.1.ptr.address.checked_add(region.ptr.address)?,
                region.len,
            ),
        ))
    }
}

unsafe impl<F: Flash> Flash for SubFlash<F> {
    #[inline]
    fn size(&self) -> Result<u32, Error> {
        Ok(self.1.len)
    }

    #[inline]
    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
        if offset.address >= self.1.len {
            return Err(Error::OutOfRange);
        }
        let offset = offset
            .address
            .checked_add(self.1.ptr.address)
            .ok_or(Error::OutOfRange)?;

        self.0.read(Ptr::new(offset), out)
    }

    #[inline]
    fn read_direct<'a: 'c, 'b: 'c, 'c>(
        &'a self,
        region: Region,
        arena: &'b dyn Arena,
        align: usize,
    ) -> Result<&'c [u8], Error> {
        if region.ptr.address >= self.1.len {
            return Err(Error::OutOfRange);
        }
        let offset = region
            .ptr
            .address
            .checked_add(self.1.ptr.address)
            .ok_or(Error::OutOfRange)?;

        self.0
            .read_direct(Region::new(offset, region.len), arena, align)
    }

    #[inline]
    fn program(&mut self, offset: Ptr, buf: &[u8]) -> Result<(), Error> {
        if offset.address >= self.1.len {
            return Err(Error::OutOfRange);
        }
        let offset = offset
            .address
            .checked_add(self.1.ptr.address)
            .ok_or(Error::OutOfRange)?;

        self.0.program(Ptr::new(offset), buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        self.0.flush()
    }
}

/// Adapter for converting RAM-backed storage into a [`Flash`].
///
/// For the purposes of this type, "RAM-backed" means that `AsRef<[u8]>`
/// is implemented.
///
/// [`Flash`]: traits.Flash.html
#[derive(Copy, Clone)]
pub struct Ram<Bytes>(pub Bytes);

unsafe impl<Bytes: AsRef<[u8]>> Flash for Ram<Bytes> {
    fn size(&self) -> Result<u32, Error> {
        self.0
            .as_ref()
            .len()
            .try_into()
            .map_err(|_| Error::Unspecified)
    }

    #[inline]
    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
        out.copy_from_slice(self.read_direct(
            Region::new(offset.address, out.len() as u32),
            &OutOfMemory,
            1,
        )?);
        Ok(())
    }

    fn read_direct<'a: 'c, 'b: 'c, 'c>(
        &'a self,
        region: Region,
        arena: &'b dyn Arena,
        align: usize,
    ) -> Result<&'c [u8], Error> {
        let start = region.ptr.address as usize;
        let end = start
            .checked_add(region.len as usize)
            .ok_or(Error::OutOfRange)?;
        if end > self.0.as_ref().len() {
            return Err(Error::OutOfRange);
        }

        let slice = &self.0.as_ref()[start..end];
        assert!(align.is_power_of_two());
        if slice.as_ptr() as usize & (align - 1) == 0 {
            return Ok(slice);
        }

        let buf = arena.alloc_aligned(slice.len(), align)?;
        buf.copy_from_slice(slice);
        Ok(buf)
    }

    fn program(&mut self, _: Ptr, _: &[u8]) -> Result<(), Error> {
        return Err(Error::Locked);
    }
}

/// Adapter for converting mutable, RAM-backed storage into a [`Flash`].
///
/// For the purposes of this type, "RAM-backed" means that `AsRef<[u8]>`
/// and `AsMut<[u8]>` are implemented.
///
/// [`Flash`]: traits.Flash.html
#[derive(Copy, Clone)]
pub struct RamMut<Bytes>(pub Bytes);

unsafe impl<Bytes: AsRef<[u8]> + AsMut<[u8]>> Flash for RamMut<Bytes> {
    fn size(&self) -> Result<u32, Error> {
        self.0
            .as_ref()
            .len()
            .try_into()
            .map_err(|_| Error::Unspecified)
    }

    #[inline]
    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
        out.copy_from_slice(self.read_direct(
            Region::new(offset.address, out.len() as u32),
            &OutOfMemory,
            1,
        )?);
        Ok(())
    }

    fn read_direct<'a: 'c, 'b: 'c, 'c>(
        &'a self,
        region: Region,
        arena: &'b dyn Arena,
        align: usize,
    ) -> Result<&'c [u8], Error> {
        let start = region.ptr.address as usize;
        let end = start
            .checked_add(region.len as usize)
            .ok_or(Error::OutOfRange)?;
        if end > self.0.as_ref().len() {
            return Err(Error::OutOfRange);
        }

        let slice = &self.0.as_ref()[start..end];
        assert!(align.is_power_of_two());
        if slice.as_ptr() as usize & (align - 1) == 0 {
            return Ok(slice);
        }

        let buf = arena.alloc_aligned(slice.len(), align)?;
        buf.copy_from_slice(slice);
        Ok(buf)
    }

    fn program(&mut self, offset: Ptr, buf: &[u8]) -> Result<(), Error> {
        let start = offset.address as usize;
        let end = start.checked_add(buf.len()).ok_or(Error::OutOfRange)?;
        if end > self.0.as_ref().len() {
            return Err(Error::OutOfRange);
        }

        self.0.as_mut()[start..end].copy_from_slice(buf);
        Ok(())
    }
}

/// A [`Read`]/[`Write`] implementation for operating on a [`Flash`] serially.
///
/// `FlashIo` also actas as an `Iterator` over the serial bytes in the [`Flash`].
///
/// [`Read`]: ../../io/read/trait.Read.html
/// [`Write`]: ../../io/write/trait.Write.html
/// [`Flash`]: trait.Flash.html
#[derive(Copy, Clone)]
pub struct FlashIo<F> {
    flash: F,
    cursor: u32,
    len: u32,
}

impl<F: Flash> FlashIo<F> {
    /// Creates a new `FlashIo`, reading/writing from the beginning of `flash`.
    pub fn new(flash: F) -> Result<Self, Error> {
        let len = flash.size()?;
        Ok(Self {
            flash,
            cursor: 0,
            len,
        })
    }

    /// Skips the cursor `bytes` bytes forward.
    ///
    /// This operation always succeeds, but attempting to read past the end of
    /// flash will always result in an error.
    pub fn skip(&mut self, bytes: usize) {
        self.cursor = self.cursor.saturating_add(bytes as u32);
    }
}

impl<F: Flash> io::Read for FlashIo<F> {
    fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), io::Error> {
        self.flash
            .read(Ptr::new(self.cursor), out)
            .map_err(|_| io::Error::Internal)?;
        self.cursor += out.len() as u32;
        Ok(())
    }

    fn remaining_data(&self) -> usize {
        self.len.saturating_sub(self.cursor) as usize
    }
}

impl<F: Flash> Iterator for FlashIo<F> {
    type Item = Result<u8, Error>;
    fn next(&mut self) -> Option<Result<u8, Error>> {
        if self.remaining_data() == 0 {
            return None;
        }

        let mut byte = [0];
        if let Err(e) = self.flash.read(Ptr::new(self.cursor), &mut byte) {
            return Some(Err(e));
        }
        self.cursor += 1;
        Some(Ok(byte[0]))
    }
}

impl<F: Flash> io::Write for FlashIo<F> {
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        self.flash
            .program(Ptr::new(self.cursor), buf)
            .map_err(|_| io::Error::Internal)?;
        self.cursor += buf.len() as u32;
        Ok(())
    }
}

/// An abstract pointer into a [`Flash`] type.
///
/// A `Ptr` needs to be used in conjunction with a [`Flash`]
/// implementation to be read from or written to.
///
/// [`Flash`]: trait.Flash.html
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, AsBytes, FromBytes)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ptr {
    /// The abstract address of this pointer.
    pub address: u32,
}

impl Ptr {
    /// Convenience method for creating a `Ptr` without having to use
    /// a struct literal.
    pub const fn new(address: u32) -> Self {
        Self { address }
    }
}

/// A region within  a [`Flash`] type.
///
/// Much like a [`Ptr`], a `Region` needs to be interpreted with
/// respect to a [`Flash`] implementation.
///
/// [`Flash`]: trait.Flash.html
/// [`Ptr`]: struct.Ptr.html
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, AsBytes, FromBytes)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Region {
    /// The base pointer for this slice.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub ptr: Ptr,
    /// The length of the slice, in bytes.
    pub len: u32,
}

impl Region {
    /// Convenience method for creating a `Region` without having to use
    /// a struct literal.
    pub const fn new(ptr: u32, len: u32) -> Self {
        Self {
            ptr: Ptr::new(ptr),
            len,
        }
    }
}
