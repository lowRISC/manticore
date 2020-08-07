// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Provides a way to ergonomically manipulate bytes as queues of bits.
//!
//! This representation is implemented by the [`BitBuf`] type. This queue
//! behavior is useful for parsing and building bitfield-like values.
//!
//! The queue moves bits from least significant to most significant:
//! - Bits are written at the least significant end.
//! - Bits are read from the most significant end (a length is used to track
//!   where this is).
//!
//! These semantics mean that the inverse operation to a sequence of writes
//! is a sequence of reads in the same order.
//!
//! [`BitBuf`]: struct.BitBuf.html

use crate::io;

/// A queue-like buffer of bits within a byte.
///
/// See the [module documentation](index.html) for more details on the
/// semantics of this data structure.
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
    pub fn read_bits(&mut self, n: usize) -> Result<u8, io::Error> {
        if self.len() < n {
            return Err(io::Error::BufferExhausted);
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
    pub fn read_bit(&mut self) -> Result<bool, io::Error> {
        self.read_bits(1).map(|b| b != 0)
    }

    /// Writes exactly `n` bits to `self`, taken as the least significant bits
    /// of `bits`.
    #[inline]
    pub fn write_bits(&mut self, n: usize, bits: u8) -> Result<(), io::Error> {
        if self.len() + n > 8 {
            return Err(io::Error::BufferExhausted);
        }

        let mask = inverse_popcnt(n);
        self.bits = self.bits.wrapping_shl(n as u32);
        self.bits |= bits & mask;
        self.len += n as u8;
        Ok(())
    }

    /// Writes a single bit, represented as a `bool`.
    #[inline]
    pub fn write_bit(&mut self, bit: bool) -> Result<(), io::Error> {
        self.write_bits(1, bit as u8)
    }

    /// Writes `n` zero bits.
    #[inline]
    pub fn write_zero_bits(&mut self, n: usize) -> Result<(), io::Error> {
        self.write_bits(n, 0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn queue() {
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
    fn edge_cases() {
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
}
