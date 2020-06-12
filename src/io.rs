// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! I/O interfaces, in lieu of [`std::io`].
//!
//! These functions and traits are mostly intended for manipulating byte
//! buffers, but they could be implemented on other types that provide a
//! read/write interface.
//!
//! [`std::io`]: https://doc.rust-lang.org/std/io/index.html

use core::mem;

/// Represents a byte as a queue of bits, for simplifying parsing bit fields
/// out of a byte.
///
/// The semantics of this buffer are roughly:
/// - Bits are written at the least significant end.
/// - Bits are read from the most significant end (a length is used to track
///   where this is).
///
/// This queue behavior means that the dual operation to a sequence of writes
/// is a sequence of reads in the same order.
pub struct BitBuf {
    // NOTE: len represents the number of *least significant* bits that
    // are part of the buffer.
    len: u8,
    bits: u8,
}

/// Returns the "inverse popcnt", the smallest byte with `n` bits set.
///
/// In other words, this function computes `2^n - 1`, accounting for overflow.
#[inline(always)]
fn inverse_popcnt(n: usize) -> u8 {
    // NOTE: if the `1` below is accientally typed at `u8`, for `n = 8` we will
    // get overflow from the shift; instead, we perform the shift using native
    // arithmetic.
    ((1usize << n) - 1) as _
}

impl BitBuf {
    /// Creates an empty `BitBuf`.
    pub fn new() -> Self {
        Self { len: 0, bits: 0 }
    }

    /// Creates a new eight-bit `BitBuf` with the given bits.
    pub fn from_bits(bits: u8) -> Self {
        Self { len: 8, bits }
    }

    /// Returns the number of bits currently in the buffer.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns the bits currently in the buffer; all bits beyond `len` are
    /// guaranteed to be zero.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Reads the `n` most significant bits from `self`, returning them as the
    /// least significant bits of a byte.
    #[inline]
    pub fn read_bits(&mut self, n: usize) -> Result<u8, Error> {
        if self.len() < n {
            return Err(Error::BufferExhausted);
        }

        // Avoid the corner-case of `n = 0` entirely, since it can trigger
        // shift underflow.
        if n == 0 {
            return Ok(0);
        }

        let mask = inverse_popcnt(n);
        let offset = self.len() - n;
        let val = (self.bits >> offset) & mask;
        self.bits &= !(mask << offset);
        self.len -= n as u8;
        Ok(val)
    }

    /// Reads a single bit, and converts it to `bool`.
    #[inline]
    pub fn read_bit(&mut self) -> Result<bool, Error> {
        self.read_bits(1).map(|b| b != 0)
    }

    /// Writes exactly `n` bits to `self`, taken as the least significant bits
    /// of `bits`.
    #[inline]
    pub fn write_bits(&mut self, n: usize, bits: u8) -> Result<(), Error> {
        if self.len() + n > 8 {
            return Err(Error::BufferExhausted);
        }

        let mask = inverse_popcnt(n);
        self.bits = self.bits.wrapping_shl(n as u32);
        self.bits |= bits & mask;
        self.len += n as u8;
        Ok(())
    }

    /// Writes a single bit, represented as a `bool`.
    #[inline]
    pub fn write_bit(&mut self, bit: bool) -> Result<(), Error> {
        self.write_bits(1, bit as u8)
    }

    /// Writes `n` zero bits.
    #[inline]
    pub fn write_zero_bits(&mut self, n: usize) -> Result<(), Error> {
        self.write_bits(n, 0)
    }
}

/// A generic, low-level I/O error.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Indicates that some underlying buffer has been completely used up,
    /// either for reading from or writing to.
    ///
    /// This is typically a fatal error, since it is probably not possible
    /// to re-allocate that unrelying buffer.
    BufferExhausted,
}

/// A little-endian integer, which can be read and written.
///
/// This trait can be used for operating generically over little-endian integer
/// I/O.
pub trait LeInt: Sized + Copy {
    /// Reads a value of type `Self`, in little-endian order.
    fn read_from<'a, R: Read<'a> + ?Sized>(r: &mut R) -> Result<Self, Error>;

    /// Writes a value of type `Self`, in little-endian order.
    fn write_to<W: Write + ?Sized>(self, w: &mut W) -> Result<(), Error>;
}

impl LeInt for u8 {
    fn read_from<'a, R: Read<'a> + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(r.read_bytes(mem::size_of::<Self>())?[0])
    }

    fn write_to<W: Write + ?Sized>(self, w: &mut W) -> Result<(), Error> {
        w.write_bytes(&[self])
    }
}

impl LeInt for u16 {
    fn read_from<'a, R: Read<'a> + ?Sized>(r: &mut R) -> Result<Self, Error> {
        use byteorder::ByteOrder as _;

        Ok(byteorder::LE::read_u16(
            r.read_bytes(mem::size_of::<Self>())?,
        ))
    }

    fn write_to<W: Write + ?Sized>(self, w: &mut W) -> Result<(), Error> {
        use byteorder::ByteOrder as _;

        let mut bytes = [0; mem::size_of::<Self>()];
        byteorder::LE::write_u16(&mut bytes, self);
        w.write_bytes(&bytes)
    }
}

impl LeInt for u32 {
    fn read_from<'a, R: Read<'a> + ?Sized>(r: &mut R) -> Result<Self, Error> {
        use byteorder::ByteOrder as _;

        Ok(byteorder::LE::read_u32(
            r.read_bytes(mem::size_of::<Self>())?,
        ))
    }

    fn write_to<W: Write + ?Sized>(self, w: &mut W) -> Result<(), Error> {
        use byteorder::ByteOrder as _;

        let mut bytes = [0; mem::size_of::<Self>()];
        byteorder::LE::write_u32(&mut bytes, self);
        w.write_bytes(&bytes)
    }
}

impl LeInt for u64 {
    fn read_from<'a, R: Read<'a> + ?Sized>(r: &mut R) -> Result<Self, Error> {
        use byteorder::ByteOrder as _;

        Ok(byteorder::LE::read_u64(
            r.read_bytes(mem::size_of::<Self>())?,
        ))
    }

    fn write_to<W: Write + ?Sized>(self, w: &mut W) -> Result<(), Error> {
        use byteorder::ByteOrder as _;

        let mut bytes = [0; mem::size_of::<Self>()];
        byteorder::LE::write_u64(&mut bytes, self);
        w.write_bytes(&bytes)
    }
}

/// Represents a place that bytes can be read from, such as a `&[u8]`.
///
/// Unlike [`std::io::Read`], this trait is intended for performing exact reads
/// out of a buffer with a fixed lifetime; hence, the additional lifetime
/// argument. In other words, a `manticore::io::Read` owns all of the data it
/// returns.
///
/// [`std::io::Read`]: https://doc.rust-lang.org/std/io/trait.Read.html
pub trait Read<'a> {
    /// Reads exactly `n` bytes from `self`.
    ///
    /// This function does not perform partial reads: it will either block
    /// until completion or return an error.
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], Error>;

    /// Returns the number of bytes still available to read.
    fn remaining_data(&self) -> usize;

    /// Reads a little-endian integer.
    fn read_le<I: LeInt>(&mut self) -> Result<I, Error> {
        I::read_from(self)
    }
}

impl<'a> Read<'a> for &'a [u8] {
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.len() < n {
            return Err(Error::BufferExhausted);
        }

        let result = &self[..n];
        *self = &self[n..];
        Ok(result)
    }

    fn remaining_data(&self) -> usize {
        return self.len();
    }
}

impl<'a> Read<'a> for &'a mut [u8] {
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.len() < n {
            return Err(Error::BufferExhausted);
        }

        let (result, rest) = mem::replace(self, &mut []).split_at_mut(n);
        *self = rest;
        Ok(result)
    }

    fn remaining_data(&self) -> usize {
        return self.len();
    }
}

/// Represents a place that bytes can be written to, such as a `&[u8]`.
pub trait Write {
    /// Attempt to write `buf` exactly to `self`.
    ///
    /// This function does not perform partial writes: it will either block
    /// until completion or return an error.
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), Error>;

    /// Returns the number of bytes still available to read.
    fn remaining_space(&self) -> usize;

    /// Writes a little-endian integer.
    fn write_le<I: LeInt>(&mut self, val: I) -> Result<(), Error> {
        val.write_to(self)
    }
}

impl Write for &'_ mut [u8] {
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), Error> {
        let n = buf.len();
        if self.len() < n {
            return Err(Error::BufferExhausted);
        }

        let (dest, rest) = mem::replace(self, &mut []).split_at_mut(n);
        dest.copy_from_slice(buf);
        *self = rest;
        Ok(())
    }

    fn remaining_space(&self) -> usize {
        return self.len();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bit_buf_queue() {
        let mut buf = BitBuf::new();
        assert_eq!(buf.bits(), 0);
        assert_eq!(buf.len(), 0);
        buf.write_bits(3, 0b101).unwrap();
        assert_eq!(buf.bits(), 0b101);
        assert_eq!(buf.len(), 3);
        buf.write_bits(2, 0b10).unwrap();
        assert_eq!(buf.bits(), 0b10110);
        assert_eq!(buf.len(), 5);
        buf.write_bit(true).unwrap();
        assert_eq!(buf.bits(), 0b101101);
        assert_eq!(buf.len(), 6);
        buf.write_zero_bits(2).unwrap();
        assert_eq!(buf.bits(), 0b10110100);
        assert_eq!(buf.len(), 8);
        assert!(buf.write_bit(true).is_err());

        assert_eq!(buf.read_bits(3).unwrap(), 0b101);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.read_bit().unwrap(), true);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.read_bits(4).unwrap(), 0b0100);
        assert_eq!(buf.len(), 0);
        assert!(buf.read_bit().is_err());
    }

    #[test]
    fn bit_bif_edge_cases() {
        let mut buf = BitBuf::from_bits(0x55);
        assert_eq!(buf.read_bits(0).unwrap(), 0);
        assert_eq!(buf.len(), 8);
        assert_eq!(buf.read_bits(8).unwrap(), 0x55);
        assert_eq!(buf.len(), 0);

        let mut buf = BitBuf::new();
        buf.write_bits(8, 0xaa).unwrap();
        assert_eq!(buf.bits(), 0xaa);
        assert_eq!(buf.len(), 8);
        buf.write_bits(0, 0x42).unwrap();
        assert_eq!(buf.bits(), 0xaa);
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn read_bytes() {
        let mut bytes: &[u8] = b"Hello!";
        assert_eq!(bytes.read_bytes(3).unwrap(), b"Hel");
        assert_eq!(bytes.len(), 3);
        assert_eq!(bytes.read_le::<u16>().unwrap(), 0x6f6c);
        assert_eq!(bytes.len(), 1);
        assert!(bytes.read_le::<u32>().is_err());
    }

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
}
