// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Provides the [`Write`] trait, analogous to [`std::io::Write`].

use core::mem;

use static_assertions::assert_obj_safe;

use crate::io;
use crate::io::endian::LeInt;

/// Represents a place that bytes can be written to, such as a `&[u8]`.
///
/// # Relation with [`std::io::Write`]
/// [`std::io::Write`] provides approximately a superset of `Write`, with
/// more detailed errors. [`StdWrite`] provides an implementation of
/// `Write` in terms of [`std::io::Write`].
pub trait Write {
    /// Attempt to write `buf` exactly to `self`.
    ///
    /// This function does not perform partial writes: it will either block
    /// until completion or return an error.
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), io::Error>;

    /// Writes a little-endian integer.
    ///
    /// # Note
    /// Do not implement this function yourself. Callers are not required to
    /// call it in order to actually perform a write, so whether or not it is
    /// called is an implementation detail.
    #[inline]
    fn write_le<I: LeInt>(&mut self, val: I) -> Result<(), io::Error>
    where
        Self: Sized,
    {
        val.write_to(self)
    }
}

assert_obj_safe!(Write);

impl<W: Write + ?Sized> Write for &'_ mut W {
    #[inline]
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        W::write_bytes(*self, buf)
    }
}

impl Write for &'_ mut [u8] {
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        let n = buf.len();
        if self.len() < n {
            return Err(io::Error::BufferExhausted);
        }

        let (dest, rest) = mem::replace(self, &mut []).split_at_mut(n);
        dest.copy_from_slice(buf);
        *self = rest;
        Ok(())
    }
}

// This allows us to refer to types via the `manticore` prefix in the
// doc comments below, which is useful for clarity between `std` and
// `manticore` IO traits.
#[cfg(doc)]
use crate as manticore;

/// Converts a [`std::io::Write`] into a [`manticore::io::Write`].
///
/// [`manticore::io::Write::write_bytes()`] is implemented by simply calling
/// [`std::io::Write::write()`] repeatedly until every byte is written;
/// [`manticore::io::Write`] should be implemented directly if possible.
///
/// This type is provided instead of implementing [`manticore::io::Write`]
/// directly for every [`std::io::Write`] due to trait coherence issues
/// involving the blanket impl on `&mut _`.
#[cfg(feature = "std")]
pub struct StdWrite<W>(pub W);

#[cfg(feature = "std")]
impl<W: std::io::Write> Write for StdWrite<W> {
    fn write_bytes(&mut self, mut buf: &[u8]) -> Result<(), io::Error> {
        use std::io::ErrorKind;
        loop {
            if buf.is_empty() {
                return Ok(());
            }
            match self.0.write(buf).map_err(|e| e.kind()) {
                Ok(len) => buf = &buf[len..],
                Err(ErrorKind::Interrupted) => continue,
                // No good way to propagate this. =/
                Err(_) => return Err(io::Error::Internal),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::io::Read;

    #[test]
    fn read_and_write_bytes() {
        let mut buf = [0; 6];
        let mut bytes = &mut buf[..];
        bytes.write_bytes(b"Wo").unwrap();
        bytes.write_bytes(b"r").unwrap();
        assert_eq!(bytes.len(), 3);
        bytes.write_le::<u16>(0x646c).unwrap();
        assert_eq!(bytes.len(), 1);
        assert!(bytes.write_bytes(b"!!").is_err());
        bytes.write_le::<u8>(b'!').unwrap();
        assert_eq!(bytes.len(), 0);
        assert_eq!(&buf, b"World!");

        let mut bytes = &mut buf[..];
        assert_eq!(bytes.read_le::<u32>().unwrap(), 0x6c726f57);
    }

    #[test]
    fn std_write() {
        let mut buf = [0; 4];
        let mut std_write = StdWrite(&mut buf[..]);
        std_write.write_le::<u32>(0x04030201).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
    }
}
