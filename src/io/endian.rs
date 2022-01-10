// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Traits for converting integers to and from byte representations.
//!
//! Integerations should never have to interact with this module directly.

use core::mem;

use crate::io;
use crate::io::Read;
use crate::io::Write;
use crate::Result;

/// A little-endian integer, which can be read and written.
///
/// This trait can be used for operating generically over little-endian integer
/// I/O.
pub trait LeInt: Sized + Copy {
    /// Reads a value of type `Self`, in little-endian order.
    fn read_from<R: Read>(r: R) -> Result<Self, io::Error>;

    /// Writes a value of type `Self`, in little-endian order.
    fn write_to<W: Write>(self, w: W) -> Result<(), io::Error>;
}

impl LeInt for u8 {
    #[inline]
    fn read_from<R: Read>(mut r: R) -> Result<Self, io::Error> {
        let mut bytes = [0; mem::size_of::<Self>()];
        r.read_bytes(&mut bytes)?;
        Ok(bytes[0])
    }

    #[inline]
    fn write_to<W: Write>(self, mut w: W) -> Result<(), io::Error> {
        w.write_bytes(&[self])
    }
}

impl LeInt for u16 {
    #[inline]
    fn read_from<R: Read>(mut r: R) -> Result<Self, io::Error> {
        use byteorder::ByteOrder as _;

        let mut bytes = [0; mem::size_of::<Self>()];
        r.read_bytes(&mut bytes)?;
        Ok(byteorder::LE::read_u16(&bytes))
    }

    #[inline]
    fn write_to<W: Write>(self, mut w: W) -> Result<(), io::Error> {
        use byteorder::ByteOrder as _;

        let mut bytes = [0; mem::size_of::<Self>()];
        byteorder::LE::write_u16(&mut bytes, self);
        w.write_bytes(&bytes)
    }
}

impl LeInt for u32 {
    #[inline]
    fn read_from<R: Read>(mut r: R) -> Result<Self, io::Error> {
        use byteorder::ByteOrder as _;

        let mut bytes = [0; mem::size_of::<Self>()];
        r.read_bytes(&mut bytes)?;
        Ok(byteorder::LE::read_u32(&bytes))
    }

    #[inline]
    fn write_to<W: Write>(self, mut w: W) -> Result<(), io::Error> {
        use byteorder::ByteOrder as _;

        let mut bytes = [0; mem::size_of::<Self>()];
        byteorder::LE::write_u32(&mut bytes, self);
        w.write_bytes(&bytes)
    }
}

impl LeInt for u64 {
    #[inline]
    fn read_from<R: Read>(mut r: R) -> Result<Self, io::Error> {
        use byteorder::ByteOrder as _;

        let mut bytes = [0; mem::size_of::<Self>()];
        r.read_bytes(&mut bytes)?;
        Ok(byteorder::LE::read_u64(&bytes))
    }

    #[inline]
    fn write_to<W: Write>(self, mut w: W) -> Result<(), io::Error> {
        use byteorder::ByteOrder as _;

        let mut bytes = [0; mem::size_of::<Self>()];
        byteorder::LE::write_u64(&mut bytes, self);
        w.write_bytes(&bytes)
    }
}
