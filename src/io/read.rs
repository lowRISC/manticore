// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Provides the [`Read`] trait, analogous to [`std::io::Read`].

use core::mem;

use static_assertions::assert_obj_safe;

use crate::io;
use crate::io::endian::LeInt;

/// Represents a place that bytes can be read from, such as a `&[u8]`.
///
/// # Relation with [`std::io::Read`]
/// [`std::io::Read`] is distinct from `Read`, since `Read` must know,
/// a-priori, the total length of the underlying buffer.
///
/// The recommended way to use a [`std::io::Read`] with a `manticore` API is to
/// use `read_to_end(&mut buf)` and to then pass `&mut buf[..]` into
/// `manticore`. We hope to remove this restriction in the future.
pub trait Read {
    /// Reads exactly `n` bytes from `self`.
    fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), io::Error>;

    /// Returns the number of bytes still available to read.
    fn remaining_data(&self) -> usize;

    /// Reads a little-endian integer.
    ///
    /// # Note
    /// Do not implement this function yourself. Callers are not required to
    /// call it in order to actually perform a read, so whether or not it is
    /// called is an implementation detail.
    #[inline]
    fn read_le<I: LeInt>(&mut self) -> Result<I, io::Error>
    where
        Self: Sized,
    {
        I::read_from(self)
    }
}
assert_obj_safe!(Read);

impl<R: Read + ?Sized> Read for &'_ mut R {
    #[inline]
    fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), io::Error> {
        R::read_bytes(*self, out)
    }

    #[inline]
    fn remaining_data(&self) -> usize {
        R::remaining_data(*self)
    }
}

impl Read for &[u8] {
    fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), io::Error> {
        let n = out.len();
        if self.len() < n {
            return Err(io::Error::BufferExhausted);
        }

        out.copy_from_slice(&self[..n]);
        *self = &self[n..];
        Ok(())
    }

    fn remaining_data(&self) -> usize {
        self.len()
    }
}

impl Read for &mut [u8] {
    fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), io::Error> {
        let n = out.len();
        if self.len() < n {
            return Err(io::Error::BufferExhausted);
        }

        out.copy_from_slice(&self[..n]);
        let buf = mem::replace(self, &mut []);
        *self = &mut buf[n..];
        Ok(())
    }

    fn remaining_data(&self) -> usize {
        self.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn read_bytes() {
        let mut bytes: &[u8] = b"Hello!";
        let mut three_bytes = [0; 3];
        bytes.read_bytes(&mut three_bytes).unwrap();
        assert_eq!(&three_bytes[..], b"Hel");
        assert_eq!(bytes.len(), 3);
        assert_eq!(bytes.read_le::<u16>().unwrap(), 0x6f6c);
        assert_eq!(bytes.len(), 1);
        assert!(bytes.read_le::<u32>().is_err());
    }
}
