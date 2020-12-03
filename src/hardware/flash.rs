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
pub trait Flash {
    /// Returns the size, in bytes, of this device.
    fn size(&self) -> Result<u32, Error>;

    /// Attempts to read `out.len()` bytes starting at `offset`.
    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error>;

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

impl<F: Flash> Flash for &F {
    #[inline]
    fn size(&self) -> Result<u32, Error> {
        F::size(self)
    }

    #[inline]
    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
        F::read(self, offset, out)
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

impl<F: Flash> Flash for &mut F {
    #[inline]
    fn size(&self) -> Result<u32, Error> {
        F::size(self)
    }

    #[inline]
    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
        F::read(self, offset, out)
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

/// A [`Flash`] type that allows for zero-copy reads.
///
/// This trait allows implementations that can support a zero-copy read,
/// perhaps due to their inherently-buffering nature, to do so directly.
///
/// Normal [`Flash`] implementations can be made to support zero-copy
/// reads by combining them with an [`Arena`]; see [`ArenaFlash`].
///
/// [`Flash`]: trait.Flash.html
/// [`ArenaFlash`]: struct.ArenaFlash.html
pub trait FlashZero: Flash {
    /// Attempts to zero-copy read the given region out of this device.
    fn read_zerocopy(&self, slice: Region) -> Result<&[u8], Error>;

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

// NOTE: implementing for &impl FlashZero doesn't make sense, because that
// would result in an unresettable FlashZero.

impl<F: FlashZero> FlashZero for &mut F {
    #[inline]
    fn read_zerocopy(&self, slice: Region) -> Result<&[u8], Error> {
        F::read_zerocopy(self, slice)
    }

    #[inline]
    fn reset(&mut self) -> Result<(), Error> {
        F::reset(self)
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

impl<F: Flash> Flash for SubFlash<F> {
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

impl<F: FlashZero> FlashZero for SubFlash<F> {
    #[inline]
    fn read_zerocopy(&self, slice: Region) -> Result<&[u8], Error> {
        if slice.ptr.address > self.1.len {
            return Err(Error::OutOfRange);
        }
        let offset = slice
            .ptr
            .address
            .checked_add(self.1.ptr.address)
            .ok_or(Error::OutOfRange)?;

        self.0.read_zerocopy(Region::new(offset, slice.len))
    }

    #[inline]
    fn reset(&mut self) -> Result<(), Error> {
        self.0.reset()
    }
}

/// Adapter for supporting "zero-copy" reads on a [`Flash`] via an [`Arena`].
///
/// This type wraps a [`Flash`] type, plus an [`Arena`], and implements
/// zero-copy reads by first allocating a buffer on the arena and then
/// using that allocation to perform a read.
///
/// [`Flash`]: trait.Flash.html
/// [`Arena`]: ../../mem/trait.Arena.html
#[derive(Copy, Clone)]
pub struct ArenaFlash<F, A>(pub F, pub A);

impl<F: Flash, A> Flash for ArenaFlash<F, A> {
    #[inline]
    fn size(&self) -> Result<u32, Error> {
        self.0.size()
    }

    #[inline]
    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
        self.0.read(offset, out)
    }

    #[inline]
    fn program(&mut self, offset: Ptr, buf: &[u8]) -> Result<(), Error> {
        self.0.program(offset, buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        self.0.flush()
    }
}

impl<F: Flash, A: Arena> FlashZero for ArenaFlash<F, A> {
    fn read_zerocopy(&self, slice: Region) -> Result<&[u8], Error> {
        let Self(flash, arena) = self;
        let buf = arena
            .alloc(slice.len as usize)
            .map_err(|_| Error::Internal)?;
        flash.read(slice.ptr, buf)?;
        Ok(buf)
    }

    #[inline]
    fn reset(&mut self) -> Result<(), Error> {
        self.1.reset();
        Ok(())
    }
}

/// Adapter for converting RAM-backed storage into a [`FlashZero`].
///
/// For the purposes of this type, "RAM-backed" means that `AsRef<[u8]>`
/// is implemented.
///
/// [`FlashZero`]: traits.Flash.html
#[derive(Copy, Clone)]
pub struct Ram<Bytes>(pub Bytes);

impl<Bytes: AsRef<[u8]>> Flash for Ram<Bytes> {
    fn size(&self) -> Result<u32, Error> {
        self.0
            .as_ref()
            .len()
            .try_into()
            .map_err(|_| Error::Unspecified)
    }

    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
        let start = offset.address as usize;
        let end = start.checked_add(out.len()).ok_or(Error::OutOfRange)?;
        if end > self.0.as_ref().len() {
            return Err(Error::OutOfRange);
        }

        out.copy_from_slice(&self.0.as_ref()[start..end]);
        Ok(())
    }

    fn program(&mut self, _: Ptr, _: &[u8]) -> Result<(), Error> {
        Err(Error::Locked)
    }
}

impl<Bytes: AsRef<[u8]>> FlashZero for Ram<Bytes> {
    fn read_zerocopy(&self, offset: Region) -> Result<&[u8], Error> {
        let start = offset.ptr.address as usize;
        let end = start
            .checked_add(offset.len as usize)
            .ok_or(Error::OutOfRange)?;
        if end > self.0.as_ref().len() {
            return Err(Error::OutOfRange);
        }

        Ok(&self.0.as_ref()[start..end])
    }
}

/// Adapter for converting mutable, RAM-backed storage into a [`FlashZero`].
///
/// For the purposes of this type, "RAM-backed" means that `AsRef<[u8]>`
/// and `AsMut<[u8]>` are implemented.
///
/// [`FlashZero`]: traits.Flash.html
#[derive(Copy, Clone)]
pub struct RamMut<Bytes>(pub Bytes);

impl<Bytes: AsRef<[u8]> + AsMut<[u8]>> Flash for RamMut<Bytes> {
    fn size(&self) -> Result<u32, Error> {
        self.0
            .as_ref()
            .len()
            .try_into()
            .map_err(|_| Error::Unspecified)
    }

    fn read(&self, offset: Ptr, out: &mut [u8]) -> Result<(), Error> {
        let start = offset.address as usize;
        let end = start.checked_add(out.len()).ok_or(Error::OutOfRange)?;
        if end > self.0.as_ref().len() {
            return Err(Error::OutOfRange);
        }

        out.copy_from_slice(&self.0.as_ref()[start..end]);
        Ok(())
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

impl<Bytes: AsRef<[u8]> + AsMut<[u8]>> FlashZero for RamMut<Bytes> {
    fn read_zerocopy(&self, offset: Region) -> Result<&[u8], Error> {
        let start = offset.ptr.address as usize;
        let end = start
            .checked_add(offset.len as usize)
            .ok_or(Error::OutOfRange)?;
        if end > self.0.as_ref().len() {
            return Err(Error::OutOfRange);
        }

        Ok(&self.0.as_ref()[start..end])
    }
}

/// A [`Read`]/[`Write`] implementation for operating on a [`Flash`] serially.
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
