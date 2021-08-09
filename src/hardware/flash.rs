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

#![allow(unsafe_code)]

use core::alloc::Layout;
use core::convert::TryInto;
use core::mem;

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::io;
use crate::io::Read as _;
use crate::mem::Arena;
use crate::mem::OutOfMemory;

#[cfg(doc)]
use crate::mem::ArenaExt;

/// A [`Flash`] error.
///
/// All of these errors are non-retryable; a [`Flash`] implementation should
/// block until the operation succeeds.
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
debug_from!(Error => OutOfMemory);

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
    fn read(&self, offset: u32, out: &mut [u8]) -> Result<(), Error>;

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
    /// # use core::alloc::Layout;
    /// # use manticore::mem::*;
    /// # use manticore::hardware::flash::*;
    /// # struct Foo;
    /// # impl Foo {
    /// # fn read(&self, offset: u32, out: &mut [u8]) -> Result<(), Error> {
    /// #   Ok(())
    /// # }
    /// fn read_direct<'a: 'c, 'b: 'c, 'c>(
    ///     &'a self,
    ///     region: Region,
    ///     arena: &'b dyn Arena,
    ///     align: usize,
    /// ) -> Result<&'c [u8], Error> {
    ///     let layout = Layout::from_size_align(region.len as usize, align).unwrap();
    ///     let mut buf = arena.alloc_raw(layout)?;
    ///     self.read(region.offset, &mut buf)?;
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
    fn program(&mut self, offset: u32, buf: &[u8]) -> Result<(), Error>;

    /// Flushes any pending `program()` operations.
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
impl dyn Flash {} // Ensure object-safety.

unsafe impl<F: Flash + ?Sized> Flash for &F {
    #[inline]
    fn size(&self) -> Result<u32, Error> {
        F::size(self)
    }

    #[inline]
    fn read(&self, offset: u32, out: &mut [u8]) -> Result<(), Error> {
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
    fn program(&mut self, _: u32, _: &[u8]) -> Result<(), Error> {
        Err(Error::Locked)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        Err(Error::Locked)
    }
}

unsafe impl<F: Flash + ?Sized> Flash for &mut F {
    #[inline]
    fn size(&self) -> Result<u32, Error> {
        F::size(self)
    }

    #[inline]
    fn read(&self, offset: u32, out: &mut [u8]) -> Result<(), Error> {
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
    fn program(&mut self, offset: u32, buf: &[u8]) -> Result<(), Error> {
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
#[extend::ext(name = FlashExt)]
pub impl<F: Flash + ?Sized> F {
    /// Reads a value of type `T`.
    ///
    /// See [`ArenaExt::alloc()`].
    fn read_object<'a: 'c, 'b: 'c, 'c, T>(
        &'a self,
        offset: u32,
        arena: &'b dyn Arena,
    ) -> Result<&'c T, Error>
    where
        T: AsBytes + FromBytes + Copy,
    {
        let bytes = self.read_direct(
            Region::new(offset, mem::size_of::<T>() as u32),
            arena,
            mem::align_of::<T>(),
        )?;

        let lv = LayoutVerified::<_, T>::new(bytes)
            .expect("read_direct() implemented incorrectly");
        Ok(lv.into_ref())
    }

    /// Reads an entire region, peeling off a header of type `T`.
    ///
    /// Returns the header and whatever bytes that follow it.
    fn read_with_header<'a: 'c, 'b: 'c, 'c, T>(
        &'a self,
        region: Region,
        arena: &'b dyn Arena,
    ) -> Result<(&'c T, &'c [u8]), Error>
    where
        T: AsBytes + FromBytes + Copy,
    {
        if region.len < mem::size_of::<T>() as u32 {
            return Err(Error::OutOfRange);
        }

        let bytes = self.read_direct(region, arena, mem::align_of::<T>())?;

        let (lv, rest) = LayoutVerified::<_, T>::new_from_prefix(bytes)
            .expect("read_direct() implemented incorrectly");
        Ok((lv.into_ref(), rest))
    }

    /// Reads a slice of type `[T]`.
    ///
    /// See [`ArenaExt::alloc_slice()`].
    fn read_slice<'a: 'c, 'b: 'c, 'c, T>(
        &'a self,
        offset: u32,
        n: usize,
        arena: &'b dyn Arena,
    ) -> Result<&'c [T], Error>
    where
        T: AsBytes + FromBytes + Copy,
    {
        let bytes_requested =
            mem::size_of::<T>().checked_mul(n).ok_or(OutOfMemory)?;
        let bytes = self.read_direct(
            Region::new(offset, bytes_requested as u32),
            arena,
            mem::align_of::<T>(),
        )?;

        let lv = LayoutVerified::<_, [T]>::new_slice(bytes)
            .expect("read_direct() implemented incorrectly");
        Ok(lv.into_slice())
    }
}

/// Adapter for converting RAM-backed storage into a [`Flash`].
///
/// For the purposes of this type, "RAM-backed" means that `AsRef<[u8]>`
/// is implemented.
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
    fn read(&self, offset: u32, out: &mut [u8]) -> Result<(), Error> {
        out.copy_from_slice(self.read_direct(
            Region::new(offset, out.len() as u32),
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
        let start = region.offset as usize;
        let end = start
            .checked_add(region.len as usize)
            .ok_or(Error::OutOfRange)?;
        if end > self.0.as_ref().len() {
            return Err(Error::OutOfRange);
        }

        let slice = &self.0.as_ref()[start..end];
        let layout = Layout::from_size_align(slice.len(), align).unwrap();
        if slice.as_ptr() as usize & (align - 1) == 0 {
            return Ok(slice);
        }

        let buf = arena.alloc_raw(layout)?;
        buf.copy_from_slice(slice);
        Ok(buf)
    }

    fn program(&mut self, _: u32, _: &[u8]) -> Result<(), Error> {
        Err(Error::Locked)
    }
}

/// Adapter for converting mutable, RAM-backed storage into a [`Flash`].
///
/// For the purposes of this type, "RAM-backed" means that `AsRef<[u8]>`
/// and `AsMut<[u8]>` are implemented.
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
    fn read(&self, offset: u32, out: &mut [u8]) -> Result<(), Error> {
        out.copy_from_slice(self.read_direct(
            Region::new(offset, out.len() as u32),
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
        let start = region.offset as usize;
        let end = start
            .checked_add(region.len as usize)
            .ok_or(Error::OutOfRange)?;
        if end > self.0.as_ref().len() {
            return Err(Error::OutOfRange);
        }

        let slice = &self.0.as_ref()[start..end];
        let layout = Layout::from_size_align(slice.len(), align).unwrap();
        if slice.as_ptr() as usize & (align - 1) == 0 {
            return Ok(slice);
        }

        let buf = arena.alloc_raw(layout)?;
        buf.copy_from_slice(slice);
        Ok(buf)
    }

    fn program(&mut self, offset: u32, buf: &[u8]) -> Result<(), Error> {
        let start = offset as usize;
        let end = start.checked_add(buf.len()).ok_or(Error::OutOfRange)?;
        if end > self.0.as_ref().len() {
            return Err(Error::OutOfRange);
        }

        self.0.as_mut()[start..end].copy_from_slice(buf);
        Ok(())
    }
}

#[cfg(doc)]
use crate::io::{Read, Write};

/// A [`Read`]/[`Write`] implementation for operating on a [`Flash`] serially.
///
/// `FlashIo` also actas as an `Iterator` over the serial bytes in the [`Flash`].
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

    /// Returns the next address that this `FlashIo` would read from.
    pub fn cursor(&self) -> u32 {
        self.cursor
    }

    /// Skips the cursor `bytes` bytes forward.
    ///
    /// This operation always succeeds, but attempting to read past the end of
    /// flash will always result in an error.
    pub fn skip_bytes(&mut self, bytes: usize) {
        self.cursor = self.cursor.saturating_add(bytes as u32);
    }

    /// Skips the "end" pointer `bytes` bytes forward.
    ///
    /// This operation always succeeds, but attempting to read past the end of
    /// flash will always result in an error.
    pub fn take_bytes(&mut self, bytes: usize) {
        self.len = self.len.saturating_sub(bytes as u32);
    }

    /// Adapts this `FlashIo` to only read bytes out from the selected
    /// `Region`.
    pub fn reslice(&mut self, region: Region) {
        self.cursor = region.offset;
        self.len = region.end();
    }
}

impl<F: Flash> io::Read for FlashIo<F> {
    fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), io::Error> {
        if self.remaining_data() == 0 {
            return Err(io::Error::BufferExhausted);
        }

        self.flash
            .read(self.cursor, out)
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
        if let Err(e) = self.flash.read(self.cursor, &mut byte) {
            return Some(Err(e));
        }
        self.cursor += 1;
        Some(Ok(byte[0]))
    }
}

impl<F: Flash> io::Write for FlashIo<F> {
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        if self.remaining_data() == 0 {
            return Err(io::Error::BufferExhausted);
        }

        self.flash
            .program(self.cursor, buf)
            .map_err(|_| io::Error::Internal)?;
        self.cursor += buf.len() as u32;
        Ok(())
    }
}

/// A region within a [`Flash`] type.
///
/// A `Region` needs to be interpreted with respect to a [`Flash`]
/// implementation; it is otherwise a dumb pointer-length pair.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, AsBytes, FromBytes)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Region {
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
    /// The base pointer for this slice.
    pub offset: u32,

    #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
    /// The length of the slice, in bytes.
    pub len: u32,
}

impl Region {
    /// Convenience method for creating a `Region` without having to use
    /// a struct literal.
    pub const fn new(offset: u32, len: u32) -> Self {
        Self { offset, len }
    }

    /// Returns a `Region` big enough to hold a `T`.
    pub const fn for_type<T>() -> Self {
        Self::new(0, mem::size_of::<T>() as u32)
    }

    /// Returns a `Region` with the given start and limit.
    ///
    /// The length is computed as `limit - start + 1`. Any overflow in
    /// this operation will cause `None` to be returned.
    ///
    /// Note that the due to overflow restrictions, the region starting at
    /// `0x0000_0000` and ending at `0xffff_ffff` cannot be represented.
    pub fn from_start_and_limit(start: u32, limit: u32) -> Option<Self> {
        let len = limit.checked_sub(start)?.checked_add(1)?;
        Some(Self::new(start, len))
    }

    /// Returns a `Region` big enough to hold a `[T]` with the given number of
    /// elements.
    ///
    /// Returns `None` on overflow`.
    pub fn for_slice<T>(n: usize) -> Option<Self> {
        Some(Self::new(0, mem::size_of::<T>().checked_mul(n)? as u32))
    }

    /// Returns the end address of `self`, pointing one past the end of it.
    pub fn end(self) -> u32 {
        self.offset.saturating_add(self.len)
    }

    /// Represents `self` as a start and a limit: an inclusive range of
    /// addresses.
    ///
    /// Returns `None` if `len == 0`, or if any overflow occurs due to the
    /// length being too large.
    pub fn start_and_limit(self) -> Option<(u32, u32)> {
        Some((
            self.offset,
            self.offset.checked_add(self.len)?.checked_sub(1)?,
        ))
    }

    /// Returns a new `Region` that comes immediately after `self`, with the
    /// given length.
    pub fn and_then(self, len: u32) -> Self {
        Self::new(self.end(), len)
    }

    /// Interprets `sub` as a subregion of `self`, returning a new `Region` of
    /// the same size as `sub`.
    ///
    /// Returns `None` if `sub` is not a subregion of `self`.
    pub fn subregion(self, sub: Region) -> Option<Self> {
        if sub.len.saturating_add(sub.offset) > self.len {
            return None;
        }

        Some(Region::new(self.offset.checked_add(sub.offset)?, sub.len))
    }

    /// Contracts `self` by dropping the first `n` bytes.
    ///
    /// Returns `None` if `n` is greater than `self.len`, or if any overflow
    /// occurs.
    pub fn skip(self, n: u32) -> Option<Self> {
        Some(Region::new(
            self.offset.checked_add(n)?,
            self.len.checked_sub(n)?,
        ))
    }

    /// Contracts `self` by dropping the last `n` bytes.
    ///
    /// Returns `None` if `n` is greater than `self.len`.
    pub fn take(self, n: u32) -> Option<Self> {
        Some(Region::new(self.offset, self.len.checked_sub(n)?))
    }
}
