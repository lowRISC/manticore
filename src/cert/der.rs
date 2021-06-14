// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! DER parsing.
//!
//! Based on BoringSSL's DER parser. See
//! https://boringssl.googlesource.com/boringssl/+/refs/heads/master/crypto/bytestring/cbs.c
//!
//! We adapt BoringSSL's parser because it is battle-tested, and because DER
//! and X.509 are a bit fussy, so owning this dependency directly rather than
//! trusting an external dependency is useful.
//!
//! Note that we reject all non-DER BER, unlike BoringSSL.

#![allow(unused)]

use crate::cert;
use crate::cert::Error;
use crate::io;
use crate::io::Read as _;

#[cfg(test)]
#[path = "der_test.rs"]
mod test;

pub const TRUE: &[u8] = &[0xff];
pub const FALSE: &[u8] = &[0x00];

/// Parse `count` big-endian bytes.
fn be(buf: &mut untrusted::Reader, count: usize) -> Result<u32, Error> {
    debug_assert!(count <= 4);
    let mut val = 0;
    for _ in 0..count {
        val <<= 8;
        val |= buf.read_byte()? as u32;
    }
    Ok(val)
}

/// A DER tag.
///
/// Unlike BoringSSL, we don't bother to parse tag numbers greater than 30,
/// because none of the tags we care about use a tag larger than that.
///
/// Tags cannot be interrogated beyond basic comparisons with existing
/// constants.
// This is encoded directly as the "first octet" of a DER tag.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tag(u8);

impl Tag {
    /// Parses a tag.
    fn parse(buf: &mut untrusted::Reader) -> Result<Self, Error> {
        let tag_byte = buf.read_byte()?;
        // We don't support extended tags.
        if tag_byte & 0x1f == 0x1f {
            return Err(Error::BadEncoding);
        }
        Ok(Self(tag_byte))
    }

    pub const BOOLEAN: Tag = Tag(0x01);
    pub const INTEGER: Tag = Tag(0x02);
    pub const BIT_STRING: Tag = Tag(0x03);
    pub const OCTET_STRING: Tag = Tag(0x04);
    pub const NULL: Tag = Tag(0x05);
    pub const OID: Tag = Tag(0x06);
    pub const SEQUENCE: Tag = Tag(0x30); // Constructed bit set.

    /// Returns a context-specific, constructed tag.
    #[allow(clippy::unusual_byte_groupings)]
    pub const fn context_specific(number: u8) -> Self {
        Self((number & 0b11111) | 0b10_1_00000)
    }
}

/// Parse a single element of a `SEQUENCE`, returning its tag and contents.
pub fn any<'cert>(
    buf: &mut untrusted::Reader<'cert>,
) -> Result<(Tag, untrusted::Input<'cert>), Error> {
    let tag = Tag::parse(buf)?;
    let len_byte = buf.read_byte()?;
    // NOTE: the header is always two bytes long.

    // If `len` has the high bit set, then it is a "long form" length.
    let len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let num_bytes = len_byte & 0x7f;

        if num_bytes == 0 || num_bytes > 4 {
            // We only support lengths at most 32 bits.
            //
            // This also catches indefinite-length constructed objects,
            // which we absolutely don't support.
            return Err(Error::BadEncoding);
        }

        let len = be(buf, num_bytes as usize)?;
        if len < 128 {
            // This should have been a short-form encoding.
            return Err(Error::BadEncoding);
        }
        if len >> ((num_bytes - 1) * 8) == 0 {
            // Superfluous zero bytes; the encoding was not
            // minimal.
            return Err(Error::BadEncoding);
        }
        len as usize
    };

    let data = buf.read_bytes(len)?;
    Ok((tag, data))
}

/// Parses an optional element of a `SEQUENCE`.
pub fn opt<'cert>(
    tag: Tag,
    buf: &mut untrusted::Reader<'cert>,
) -> Result<Option<untrusted::Input<'cert>>, Error> {
    if !buf.peek(tag.0) {
        return Ok(None);
    }
    let (_, data) = any(buf)?;
    Ok(Some(data))
}

/// Parses a required element of a `SEQUENCE`.
pub fn parse<'cert>(
    tag: Tag,
    buf: &mut untrusted::Reader<'cert>,
) -> Result<untrusted::Input<'cert>, Error> {
    opt(tag, buf)?.ok_or(Error::BadEncoding)
}

/// Parses a required element of a `SEQUENCE`, passing the buffer to `dec` for further decoding.
#[inline]
pub fn tagged<'cert, T>(
    tag: Tag,
    buf: &mut untrusted::Reader<'cert>,
    dec: impl FnOnce(&mut untrusted::Reader<'cert>) -> Result<T, Error>,
) -> Result<T, Error> {
    parse(tag, buf)?.read_all(Error::BadEncoding, dec)
}

/// Parses a `BIT STRING`, ensuring that its length is divisible by 8.
#[inline]
pub fn bits_total<'cert>(
    buf: &mut untrusted::Reader<'cert>,
) -> Result<untrusted::Input<'cert>, Error> {
    bits_checked(buf, true)
}

/// Parses a `BIT STRING`, ensuring that its trailing bits are zero.
#[inline]
pub fn bits_partial<'cert>(
    buf: &mut untrusted::Reader<'cert>,
) -> Result<untrusted::Input<'cert>, Error> {
    bits_checked(buf, false)
}

fn bits_checked<'cert>(
    buf: &mut untrusted::Reader<'cert>,
    ensure_octets: bool,
) -> Result<untrusted::Input<'cert>, Error> {
    tagged(Tag::BIT_STRING, buf, |buf| {
        // A bit string is lead by a bit specifying how much padding the
        // string has.
        match buf.read_byte()? {
            // Zero is always ok.
            0 => {
                if buf.at_end() {
                    return Err(Error::BadEncoding);
                }
                Ok(buf.read_bytes_to_end())
            }

            // If we specifically requested octets, reject extra padding.
            _ if ensure_octets => Err(Error::BadEncoding),

            extra @ 1..=7 => {
                let rest = buf.read_bytes_to_end();
                let last = *rest
                    .as_slice_less_safe()
                    .last()
                    .ok_or(Error::BadEncoding)?;

                // Check that the top `extra` bits are all zero.
                let mask = (1 << extra) - 1;
                if (last & mask != 0) {
                    return Err(Error::BadEncoding);
                }

                Ok(rest)
            }

            // Too many extra bits.
            _ => Err(Error::BadEncoding),
        }
    })
}

/// Parses a non-negative `INTEGER`.
///
/// We reject all integers with the sign bit set.
pub fn uint<'cert>(
    buf: &mut untrusted::Reader<'cert>,
) -> Result<untrusted::Input<'cert>, Error> {
    let (tag, data) = any(buf)?;
    if tag != Tag::INTEGER {
        return Err(Error::BadEncoding);
    }
    data.read_all(Error::BadEncoding, |buf| {
        // `data` must be non-empty.
        let first = buf.read_byte()?;

        // `[0x00]` is the valid representation of `0`.
        if first == 0 && buf.at_end() {
            return Ok(());
        }

        // Check the sign bit; negative values are forbidden.
        if first & 0x80 != 0 {
            return Err(Error::BadEncoding);
        }

        // A leading zero is only permitted if the byte that
        // follows has a high bit set, to disambiguate
        // `-128 == [0x80]` from `128 == [0x00, 0x80]`.
        if first == 0 && buf.read_byte()? & 0x80 == 0 {
            return Err(Error::BadEncoding);
        }

        buf.skip_to_end();
        Ok(())
    })?;
    Ok(data)
}

/// Parses an non-negative `INTEGER`, up to four bytes.
pub fn u32(buf: &mut untrusted::Reader) -> Result<u32, Error> {
    uint(buf)?.read_all(Error::BadEncoding, |buf| {
        let mut v: u32 = 0;
        let mut octets = 0;
        while let Ok(b) = buf.read_byte() {
            if octets >= 4 {
                return Err(Error::BadEncoding);
            }
            v <<= 8;
            v |= b as u32;
            octets += 1;
        }
        Ok(v)
    })
}

/// Parses an optional, non-negative `INTEGER`, up to four bytes.
pub fn opt_u32(buf: &mut untrusted::Reader) -> Result<Option<u32>, Error> {
    if !buf.peek(Tag::INTEGER.0) {
        return Ok(None);
    }
    u32(buf).map(Some)
}

/// Parses a `NULL`.
pub fn null(buf: &mut untrusted::Reader) -> Result<(), Error> {
    tagged(Tag::NULL, buf, |mut buf| {
        if buf.at_end() {
            Ok(())
        } else {
            Err(Error::BadEncoding)
        }
    })
}

/// Parses an `OBJECT IDENTIFIER`. The only purpose of an OID is to be compared
/// to other OIDs byte-for-byte.
pub fn oid<'cert>(
    buf: &mut untrusted::Reader<'cert>,
) -> Result<Oid<'cert>, Error> {
    Ok(Oid::new(parse(Tag::OID, buf)?.as_slice_less_safe()))
}

pub fn opt_bool(buf: &mut untrusted::Reader) -> Result<Option<bool>, Error> {
    match &opt(Tag::BOOLEAN, buf)? {
        None => Ok(None),
        Some(b) if b == FALSE => Ok(Some(false)),
        Some(b) if b == TRUE => Ok(Some(true)),
        _ => Err(Error::BadEncoding),
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Oid<'cert>(&'cert [u8]);

impl<'cert> Oid<'cert> {
    pub const fn new(der: &'cert [u8]) -> Self {
        Self(der)
    }
}

/// Generates a new [`Oid`] constant with the given components.
macro_rules! oid {
    ($($val:literal),* $(,)?) => {{
        const LEN: usize = [$($val),*].len();
        const OID: [u32; LEN] = [$($val),*];
        const ENC_RAW: ([u8; LEN * 4], usize) = {
            let mut buf = [0u8; LEN * 4];
            let mut len = 0;

            // An OID is an array of at least two integers encoded as follows:
            // - First, a single byte containing the first two integers,
            //   encoded by the line below.
            // - Then, for each integer, encode it in base 128 (i.e., seven
            //   bits to a byte) in big-endian order. All bytes except the
            //   last have the high bit set.
            buf[0] = (OID[0] * 40 + OID[1]) as u8;
            len += 1;

            let mut idx = 2;
            while idx < LEN {
                let mut c = OID[idx];
                idx += 1;

                // Encode the component in base 128, but in
                // little-endian order because that's easier.
                // We then reverse it after the fact below.
                let mark = len;
                let mut first = true;
                while c != 0 {
                    buf[len] = (c & 0x7f) as u8;
                    if !first {
                        buf[len] |= 0x80;
                    }

                    c >>= 7;
                    first = false;
                    len += 1;
                }

                // No `const` reverse() yet, so we have to do it by hand.
                let mut idx = 0;
                #[allow(clippy::manual_swap)]
                while idx < (len - mark) / 2 {
                    let tmp = buf[mark + idx];
                    buf[mark + idx] = buf[len - idx - 1];
                    buf[len - idx - 1] = tmp;
                    idx += 1;
                }
            }
            (buf, len)
        };

        // Slicing is currently not available in `const`, so we simply copy
        // the array to another one of the correct size.
        const ENC: [u8; ENC_RAW.1] = {
            let mut buf = [0u8; ENC_RAW.1];
            let mut idx = 0;
            while idx < buf.len() {
                buf[idx] = ENC_RAW.0[idx];
                idx += 1;
            }
            buf
        };

        $crate::cert::der::Oid::<'static>::new(&ENC)
    }}
}
