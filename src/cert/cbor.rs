// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! CBOR parsing.
//!
//! This is not a complete CBOR parser, since we do not parse any CBOR not
//! needed for COSE or CWT. We also reject all CBOR that is not encoded
//! according to S4.2.1 "Core Deterministic Encoding Requirements". Concisely:
//! - No tags, floats, bools, null, or undefined.
//! - All map keys are strings or ints (though we currently only use integer
//!   keys, so we might drop string keys to cut down on complexity).
//! - All map keys are ordered lexicographically.
//!
//! Currently, this parser rejects 64-bit integers, since there is no reason
//! to encounter them in our regime, and helps cut down on code size.
//!
//! See: https://datatracker.ietf.org/doc/html/rfc8949

use core::cmp::Ord;
use core::cmp::Ordering;
use core::cmp::PartialOrd;
use core::convert::TryInto as _;

use crate::cert::Error;

#[cfg(test)]
#[path = "cbor_macro.rs"]
#[macro_use]
mod cbor_macro;

#[cfg(test)]
#[path = "cbor_test.rs"]
mod test;

// NOTE: the orderings of fields in `Int` and `Scalar` are significant, because
// they ensure that the generated derive(Ord) implementation is consistent with
// bytewise lexicographic ordering. This is enforced by the below test.
#[test]
fn scalar_ordering() {
    let ordering = [
        Scalar::Int(0.into()),
        Scalar::Int(23.into()),
        Scalar::Int(200.into()),
        Scalar::Int(1000.into()),
        Scalar::Int(100_000.into()),
        Scalar::Int((-1).into()),
        Scalar::Int((-23).into()),
        Scalar::Int((-200).into()),
        Scalar::Int((-1000).into()),
        Scalar::Int((-100_000).into()),
        Scalar::Utf8("z"),
        Scalar::Utf8("aa"),
        Scalar::Bytes(b"z"),
        Scalar::Bytes(b"aa"),
    ];
    for w in ordering.windows(2) {
        assert!(w[0] < w[1], "expected {:?} < {:?}", w[0], w[1]);
    }
}

/// A CBOR 33-bit integer.
///
/// CBOR integers are a weird sign-and-magnitude thing where they map onto
/// N+1-bit integers.
// When the bool part is `false`, the value is just the `u32` part; when it's
// `true`, the value is `-n-1`, where n is the `u32` part.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Int(bool, u32);

impl Int {
    pub const fn from_u32(n: u32) -> Self {
        Int(false, n)
    }

    pub const fn from_i32(n: i32) -> Self {
        if n >= 0 {
            Int(false, n as u32)
        } else {
            Int(true, -(n + 1) as u32)
        }
    }
}

impl From<u32> for Int {
    fn from(n: u32) -> Self {
        Int::from_u32(n)
    }
}

impl From<i32> for Int {
    fn from(n: i32) -> Self {
        Int::from_i32(n)
    }
}

/// A scalar value, e.g., once which does not require recursing into the
/// parser.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Scalar<'input> {
    Int(Int),
    Bytes(&'input [u8]),
    Utf8(&'input str),
}

impl PartialOrd for Scalar<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// NOTE: This needs to be implemented manually, since Rust defines slice
// equality such that "aa" > "z", even though "z" < "aa" in deterministic
// CBOR.
impl Ord for Scalar<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        use Scalar::*;
        match (self, other) {
            (Int(a), Int(b)) => Ord::cmp(a, b),
            (Int(_), _) => Ordering::Less,
            (_, Int(_)) => Ordering::Greater,

            (Utf8(a), Utf8(b)) => {
                Ord::cmp(&a.len(), &b.len()).then_with(|| Ord::cmp(a, b))
            }
            (Utf8(_), _) => Ordering::Less,
            (_, Utf8(_)) => Ordering::Greater,

            (Bytes(a), Bytes(b)) => {
                Ord::cmp(&a.len(), &b.len()).then_with(|| Ord::cmp(a, b))
            }
        }
    }
}

impl From<Int> for Scalar<'_> {
    fn from(i: Int) -> Self {
        Self::Int(i)
    }
}

/// A CBOR item, which can be a [`Scalar`], an [`Array`], or a [`Map`].
#[must_use = "parsing will not be driven to completion without consuming \
this value"]
pub enum Item<'input, 'reader> {
    Scalar(Scalar<'input>),
    Array(Array<'input, 'reader>),
    Map(Map<'input, 'reader>),
}

impl<'i, 'r> Item<'i, 'r> {
    /// Parses a single CBOR item.
    pub fn parse(buf: &'r mut untrusted::Reader<'i>) -> Result<Self, Error> {
        let initial = buf.read_byte()?;

        // Pull out the "argument", which is at most eight following bytes.
        // For determinism, we *require* that the minimal encoding is used.
        let argument = match initial & 0b00011111 {
            b @ 0..=23 => b as u32,

            24 => {
                let n = buf.read_byte()?;
                if n < 24 {
                    return Err(Error::BadEncoding);
                }

                n as u32
            }

            25 => {
                let slice = buf.read_bytes(2)?.as_slice_less_safe();
                let bytes: [u8; 2] = slice.try_into().unwrap();

                let n = u16::from_be_bytes(bytes);
                if n < u8::MAX as u16 {
                    return Err(Error::BadEncoding);
                }

                n as u32
            }

            26 => {
                let slice = buf.read_bytes(4)?.as_slice_less_safe();
                let bytes: [u8; 4] = slice.try_into().unwrap();

                let n = u32::from_be_bytes(bytes);
                if n < u16::MAX as u32 {
                    return Err(Error::BadEncoding);
                }

                n
            }

            // 27 is 64-bit integers, which we don't handle currently;
            // 28-30 are reserved;
            // 31 is indefinite-length encoding, which is banned.
            _ => return Err(Error::BadEncoding),
        };

        match initial >> 5 {
            sign @ 0..=1 => {
                Ok(Item::Scalar(Scalar::Int(Int(sign == 1, argument))))
            }
            2 => Ok(Item::Scalar(Scalar::Bytes(
                buf.read_bytes(argument as usize)?.as_slice_less_safe(),
            ))),
            3 => {
                let bytes =
                    buf.read_bytes(argument as usize)?.as_slice_less_safe();
                Ok(Item::Scalar(Scalar::Utf8(
                    core::str::from_utf8(bytes)
                        .map_err(|_| Error::BadEncoding)?,
                )))
            }
            4 => Ok(Item::Array(Array { buf, len: argument })),
            5 => Ok(Item::Map(Map {
                buf,
                len: argument,
                prev_key: None,
                current_key: None,
            })),
            _ => Err(Error::BadEncoding),
        }
    }

    /// Folds this item into an [`Int`].
    pub fn into_int(self) -> Result<Int, Error> {
        match self {
            Item::Scalar(Scalar::Int(i)) => Ok(i),
            _ => Err(Error::BadEncoding),
        }
    }

    /// Folds this item into a UTF-8 string.
    pub fn into_utf8(self) -> Result<&'i str, Error> {
        match self {
            Item::Scalar(Scalar::Utf8(b)) => Ok(b),
            _ => Err(Error::BadEncoding),
        }
    }

    /// Folds this item into a byte string.
    pub fn into_bytes(self) -> Result<&'i [u8], Error> {
        match self {
            Item::Scalar(Scalar::Bytes(b)) => Ok(b),
            _ => Err(Error::BadEncoding),
        }
    }

    /// Folds this item into an [`Array`].
    pub fn into_array(self) -> Result<Array<'i, 'r>, Error> {
        match self {
            Item::Array(a) => Ok(a),
            _ => Err(Error::BadEncoding),
        }
    }

    /// Folds this item into a [`Map`].
    pub fn into_map(self) -> Result<Map<'i, 'r>, Error> {
        match self {
            Item::Map(m) => Ok(m),
            _ => Err(Error::BadEncoding),
        }
    }

    /// Ignores this element, driving its internal state to completion.
    pub fn ignore(self) -> Result<(), Error> {
        match self {
            Item::Array(a) => a.with(|e| e.ignore()),
            Item::Map(m) => m.walk(|_| Ok(())),
            _ => Ok(()),
        }
    }
}

// NOTE: Array and Map cannot be iterators, because the result value needs to
// capture the &mut self lifetime.

/// A CBOR array.
///
/// The `with()` function should be used to drive parsing forward.
#[must_use = "parsing will not be driven to completion without calling `with()`"]
pub struct Array<'input, 'reader> {
    buf: &'reader mut untrusted::Reader<'input>,
    len: u32,
}

impl<'i, 'r> Array<'i, 'r> {
    /// Runs `body` on each item in the array until completion or parse failure.
    pub fn with(
        self,
        mut body: impl FnMut(Item<'i, '_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for _ in 0..self.len {
            body(Item::parse(&mut *self.buf)?)?
        }
        Ok(())
    }
}

/// A CBOR map.
///
/// Because maps are not random-access, they need to be *walked* using the
/// `walk()` function, which returns a sort of iterator that can be used to
/// retrieve mappings.
///
/// Because CBOR maps' keys are ordered, it is possible to request keys
/// one-by-one in lexicographic order, making parsing much closer to something
/// like DER.
#[must_use = "parsing will not be driven to completion without calling `walk()`"]
pub struct Map<'input, 'reader> {
    buf: &'reader mut untrusted::Reader<'input>,
    len: u32,
    prev_key: Option<Scalar<'input>>,
    current_key: Option<Scalar<'input>>,
}

impl<'i, 'r> Map<'i, 'r> {
    fn peek(&mut self) -> Result<Option<Scalar<'i>>, Error> {
        if let Some(key) = self.current_key {
            return Ok(Some(key));
        }

        if self.len == 0 {
            return Ok(None);
        }
        self.len -= 1;

        let k = match Item::parse(&mut *self.buf) {
            Ok(Item::Scalar(i @ Scalar::Int { .. })) => i,
            Ok(Item::Scalar(s @ Scalar::Utf8(..))) => s,
            _ => return Err(Error::BadEncoding),
        };

        // Map key encodings must be in lexicographic order, and duplicate keys
        // are not permitted.
        if let Some(prev) = self.prev_key {
            if prev >= k {
                return Err(Error::BadEncoding);
            }
        }

        self.current_key = Some(k);
        Ok(Some(k))
    }

    /// Drive forward the parse by peeling off the next pair in the map.
    fn next(&mut self) -> Result<Option<(Scalar<'i>, Item<'i, '_>)>, Error> {
        self.peek()?;
        let k = match self.current_key.take() {
            Some(k) => k,
            None => return Ok(None),
        };

        self.prev_key = Some(k);
        Item::parse(&mut *self.buf).map(move |v| Some((k, v)))
    }

    /// Starts a walk through `self`.
    pub fn walk<R>(
        self,
        mut body: impl FnMut(&mut MapWalker<'i, '_>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let mut walker = MapWalker {
            map: self,
            last_get: None,
        };
        let val = body(&mut walker)?;
        walker.with(|(_, v)| v.ignore())?;
        Ok(val)
    }
}

/// A walker for a [`Map`].
pub struct MapWalker<'input, 'reader> {
    map: Map<'input, 'reader>,
    last_get: Option<Scalar<'input>>,
}

impl<'i, 'r> MapWalker<'i, 'r> {
    /// Steps through the [`Map`] until `key` is reached.
    ///
    /// Note that this function should not be called with a key less than the
    /// previous one.
    pub fn get(
        &mut self,
        key: impl Into<Scalar<'i>>,
    ) -> Result<Option<Item<'i, '_>>, Error> {
        self.get_inner(key.into())
    }

    fn get_inner(
        &mut self,
        key: Scalar<'i>,
    ) -> Result<Option<Item<'i, '_>>, Error> {
        if let Some(last) = self.last_get {
            debug_assert!(last < key, "bad key order: {:?} >= {:?}", last, key);
        }
        self.last_get = Some(key);

        while let Some(next) = self.map.peek()? {
            match Ord::cmp(&next, &key) {
                // We're still in front of `key`, keep searching.
                Ordering::Less => {
                    self.map.next()?.map(|(_, v)| v.ignore()).transpose()?;
                }
                // We found it!
                Ordering::Equal => return Ok(self.map.next()?.map(|(_, v)| v)),
                // We missed it, so we give up.
                Ordering::Greater => break,
            }
        }
        Ok(None)
    }

    /// Like `get()`, but failure is an encoding error.
    pub fn must_get(
        &mut self,
        key: impl Into<Scalar<'i>>,
    ) -> Result<Item<'i, '_>, Error> {
        self.get(key)?.ok_or(Error::BadEncoding)
    }

    /// Runs `body` on remaining key-value pair in the map until completion or parse
    /// failure.
    pub fn with(
        &mut self,
        mut body: impl FnMut((Scalar<'i>, Item<'i, '_>)) -> Result<(), Error>,
    ) -> Result<(), Error> {
        while let Some(pair) = self.map.next()? {
            body(pair)?
        }
        Ok(())
    }
}
