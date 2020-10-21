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

use core::convert::TryInto;

use static_assertions::assert_obj_safe;

use zerocopy::AsBytes;
use zerocopy::FromBytes;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::io;
use crate::mem::Arena;

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

/// Provides access to a flash-like storage device.
///
/// This trait provides abstract operations on a device, as if it were a
/// block of random-access memory. It is the implementation's responsibility
/// to implement these operations efficiently with respect to the underlying
/// device.
///
/// The `Flash` trait comes implemented for `[u8]`.
pub trait Flash {
    /// Returns the size, in bytes, of this device.
    fn size(&self) -> Result<u32, Error>;

    /// Attempts to read `out.len()` bytes starting at `offset`.
    fn read(&self, offset: FlashPtr, out: &mut [u8]) -> Result<(), Error>;

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
    fn program(&mut self, offset: FlashPtr, buf: &[u8]) -> Result<(), Error>;

    /// Flushes any pending `program()` operations.
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
assert_obj_safe!(Flash);

impl<F: Flash> Flash for &mut F {
    #[inline]
    fn size(&self) -> Result<u32, Error> {
        F::size(self)
    }

    #[inline]
    fn read(&self, offset: FlashPtr, out: &mut [u8]) -> Result<(), Error> {
        F::read(self, offset, out)
    }

    #[inline]
    fn program(&mut self, offset: FlashPtr, buf: &[u8]) -> Result<(), Error> {
        F::program(self, offset, buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        F::flush(self)
    }
}

/// A [`Flash`] type that allows for zero-copy reads.
///
/// This trait allows implementations that can support a zero-copy read,
/// perhaps due to their inherently-buffering nature, to do so directly.
///
/// Normal [`Flash`] implementations can be made to support zero-copy
/// reads by combining them with an [`Arena`]; see [`ArenaFlash`].
///
/// `[u8]` implements this trait with no overhead.
///
/// [`Flash`]: trait.Flash.html
/// [`ArenaFlash]: struct.ArenaFlash.html
pub trait FlashZero: Flash {
    /// Attempts to zero-copy read the given region out of this device.
    fn read_zerocopy(&self, slice: FlashSlice) -> Result<&[u8], Error>;

    /// Hints to the implementation that it can release any buffered contents
    /// it is currently holding.
    ///
    /// See [`Arena::reset()`].
    ///
    /// [`Arena::reset()`]: ../../mem/trait.Arena.html#tymethod.reset
    fn reset(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
assert_obj_safe!(FlashZero);

impl<F: FlashZero> FlashZero for &mut F {
    #[inline]
    fn read_zerocopy(&self, slice: FlashSlice) -> Result<&[u8], Error> {
        F::read_zerocopy(self, slice)
    }

    #[inline]
    fn reset(&mut self) -> Result<(), Error> {
        F::reset(self)
    }
}

/// Shim for supporting "zero-copy" reads on a [`Flash`] via an [`Arena`].
///
/// This type wraps a [`Flash`] type, plus an [`Arena`], and implements
/// zero-copy reads by first allocating a buffer on the arena and then
/// using that allocation to perform a read.
///
/// [`Flash`]: trait.Flash.html
/// [`Arena`]: ../../mem/trait.Arena.html
pub struct ArenaFlash<F, A>(pub F, pub A);

impl<F: Flash, A> Flash for ArenaFlash<F, A> {
    #[inline]
    fn size(&self) -> Result<u32, Error> {
        self.0.size()
    }

    #[inline]
    fn read(&self, offset: FlashPtr, out: &mut [u8]) -> Result<(), Error> {
        self.0.read(offset, out)
    }

    #[inline]
    fn program(&mut self, offset: FlashPtr, buf: &[u8]) -> Result<(), Error> {
        self.0.program(offset, buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        self.0.flush()
    }
}

impl<F: Flash, A: Arena> FlashZero for ArenaFlash<F, A> {
    fn read_zerocopy(&self, slice: FlashSlice) -> Result<&[u8], Error> {
        let Self(flash, arena) = self;
        let buf = arena
            .alloc(slice.len as usize)
            .map_err(|_| Error::Internal)?;
        flash.read(slice.ptr, buf)?;
        Ok(buf)
    }

    #[inline]
    fn reset(&mut self) -> Result<(), Error> {
        Ok(self.1.reset())
    }
}

/// A [`Read`]/[`Write`] implementation for operating on a [`Flash`] serially.
///
/// [`Read`]: ../../io/read/trait.Read.html
/// [`Write`]: ../../io/write/trait.Write.html
/// [`Flash`]: trait.Flash.html
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
            .read(FlashPtr::new(self.cursor), out)
            .map_err(|_| io::Error::Internal)?;
        self.cursor += out.len() as u32;
        Ok(())
    }

    fn remaining_data(&self) -> usize {
        self.len.saturating_sub(self.cursor) as usize
    }
}

impl<F: Flash> io::Write for FlashIo<F> {
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        self.flash
            .program(FlashPtr::new(self.cursor), buf)
            .map_err(|_| io::Error::Internal)?;
        self.cursor += buf.len() as u32;
        Ok(())
    }
}

/// An abstract pointer into a [`Flash`] type.
///
/// A `FlashPtr` needs to be used in conjunction with a [`Flash`]
/// implementation to be read from or written to.
///
/// [`Flash`]: trait.Flash.html
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, AsBytes, FromBytes)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FlashPtr {
    /// The abstract address of this pointer.
    pub address: u32,
}

impl FlashPtr {
    /// Convenience method for creating a `FlashPtr` without having to use
    /// a struct literal.
    pub const fn new(address: u32) -> Self {
        Self { address }
    }
}

/// An abstrace slice into a [`Flash`] type.
///
/// Much like a [`FlashPtr`], a `FlashSlice` needs to be interpreted with
/// respect to a [`Flash`] implementation.
///
/// [`Flash`]: trait.Flash.html
/// [`FlashPtr`]: trait.FlashPtr.html
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, AsBytes, FromBytes)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FlashSlice {
    /// The base pointer for this slice.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub ptr: FlashPtr,
    /// The length of the slice, in bytes.
    pub len: u32,
}

impl FlashSlice {
    /// Convenience method for creating a `FlashSlice` without having to use
    /// a struct literal
    pub const fn new(ptr: u32, len: u32) -> Self {
        Self {
            ptr: FlashPtr::new(ptr),
            len,
        }
    }
}

/// An unspecified out-of-bounds error.
#[derive(Copy, Clone, Debug)]
pub struct OutOfBounds;

impl Flash for [u8] {
    fn size(&self) -> Result<u32, Error> {
        self.len().try_into().map_err(|_| Error::Unspecified)
    }

    fn read(&self, offset: FlashPtr, out: &mut [u8]) -> Result<(), Error> {
        let start = offset.address as usize;
        let end = start.checked_add(out.len()).ok_or(Error::OutOfRange)?;
        if end >= self.len() {
            return Err(Error::OutOfRange);
        }

        out.copy_from_slice(&self[start..end]);
        Ok(())
    }

    fn program(&mut self, offset: FlashPtr, buf: &[u8]) -> Result<(), Error> {
        let start = offset.address as usize;
        let end = start.checked_add(buf.len()).ok_or(Error::OutOfRange)?;
        if end >= self.len() {
            return Err(Error::OutOfRange);
        }

        self[start..end].copy_from_slice(buf);
        Ok(())
    }
}

impl FlashZero for [u8] {
    fn read_zerocopy(&self, offset: FlashSlice) -> Result<&[u8], Error> {
        let start = offset.ptr.address as usize;
        let end = start
            .checked_add(offset.len as usize)
            .ok_or(Error::OutOfRange)?;
        if end >= self.len() {
            return Err(Error::OutOfRange);
        }

        Ok(&self[start..end])
    }
}
