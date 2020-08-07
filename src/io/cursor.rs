// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Provides a "cursor" over a mutable byte buffer.
//!
//! [`Cursor`] provides a `consume()` function, which can be called repeatedly
//! to take portions of the buffer. An internal cursor will track the location
//! of the buffer. This method is used to implement [`Write`] for [`Cursor`].
//!
//! This type is useful when you want to feed a scratch buffer into a function
//! that performs I/O operations on a buffer, and then extract how much of the
//! buffer was read or written. This is especialy useful when used in
//! conjunction with [`ToWire`]:
//! ```
//! # use manticore::io::*;
//! # use manticore::protocol::wire::*;
//! # struct MyMessage;
//! # impl ToWire for MyMessage {
//! #     fn to_wire<W: Write>(&self, mut w: W) -> Result<(), ToWireError> {
//! #         w.write_bytes(&[1, 2, 3, 4]);
//! #         Ok(())
//! #     }
//! # }
//! let msg = MyMessage;
//! let mut buf = [0; 256];
//!
//! let mut cursor = Cursor::new(&mut buf);
//! msg.to_wire(&mut cursor);
//!
//! let msg_bytes = cursor.take_consumed_bytes();
//! assert_ne!(msg_bytes.len(), 0);
//! ```
//!
//! [`Cursor`]: struct.Cursor.html
//! [`Write`]: ../trait.Write.html
//! [`ToWire`]: ../../protocol/wire/trait.ToWire.html

use core::mem;

use crate::io;
use crate::io::Write;

/// A cursor over a buffer of memory.
///
/// See the [module documentation](index.html) for more information.
pub struct Cursor<'a> {
    buf: &'a mut [u8],
    // Invariant: cursor <= buf.len().
    cursor: usize,
}

impl<'a> Cursor<'a> {
    /// Creates a new `Cursor` for the given buffer.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, cursor: 0 }
    }

    /// Consumes `n` bytes from the underlying buffer.
    ///
    /// If `n` bytes are unavailable, `BufferExhausted` is returned.
    pub fn consume(&mut self, n: usize) -> Result<&mut [u8], io::Error> {
        let end = self
            .cursor
            .checked_add(n)
            .ok_or(io::Error::BufferExhausted)?;
        if self.buf.len() < end {
            return Err(io::Error::BufferExhausted);
        }
        let output = &mut self.buf[self.cursor..end];
        self.cursor = end;

        Ok(output)
    }

    /// Returns the number of bytes consumed thus far.
    pub fn consumed_len(&self) -> usize {
        self.cursor
    }

    /// Returns the portion of the buffer which has been consumed thus far.
    pub fn consumed_bytes(&self) -> &[u8] {
        &self.buf[..self.cursor]
    }

    /// Takes the portion of the buffer which has been consumed so far,
    /// resetting the cursor value back to zero.
    ///
    /// This function leaves `self` as if it had been newly initialized with
    /// the unconsumed portion of the buffer. Repeatedly calling this function
    /// with no other intervening operations will return `&mut []`.
    ///
    /// Because this function returns a `'a` reference, it is not bound to the
    /// `Cursor` that originally contained it. This function is useful when
    /// a desired reference needs to have the lifetime of the buffer that went
    /// into the `Cursor`, rather than the `Cursor`'s own local lifetime.
    pub fn take_consumed_bytes(&mut self) -> &'a mut [u8] {
        let (output, rest) =
            mem::replace(&mut self.buf, &mut []).split_at_mut(self.cursor);
        self.cursor = 0;
        self.buf = rest;
        output
    }
}

impl Write for Cursor<'_> {
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        let dest = self.consume(buf.len())?;
        dest.copy_from_slice(buf);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cursor() {
        let mut buf = [0; 8];
        let mut cursor = Cursor::new(&mut buf);

        cursor.write_le::<u32>(0xffaaffaa).unwrap();
        assert_eq!(cursor.consumed_len(), 4);
        assert_eq!(cursor.consumed_bytes(), &[0xaa, 0xff, 0xaa, 0xff]);
        let bytes = cursor.take_consumed_bytes();
        assert_eq!(bytes, &[0xaa, 0xff, 0xaa, 0xff]);
        assert_eq!(cursor.consumed_len(), 0);

        assert!(cursor.write_bytes(&[0x55; 7]).is_err());
    }
}
