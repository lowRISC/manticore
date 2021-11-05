// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Internal `serde` helpers.

#![allow(clippy::from_str_radix_10)]
// Some configurations may not use every helper defined here.
#![allow(unused)]

use core::any::type_name;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt;
use core::fmt::Binary;
use core::fmt::LowerHex;
use core::fmt::Write as _;
use core::marker::PhantomData;
use core::mem;

#[cfg(feature = "std")]
use std::borrow::Cow;

use serde::de;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serializer;

/// No-std helper for using as a `write!()` target.
struct ArrayBuf<const N: usize>([u8; N], usize);

impl<const N: usize> AsRef<str> for ArrayBuf<N> {
    fn as_ref(&self) -> &str {
        core::str::from_utf8(&self.0[..self.1]).unwrap()
    }
}

impl<const N: usize> Default for ArrayBuf<N> {
    fn default() -> Self {
        Self([0; N], 0)
    }
}

impl<const N: usize> fmt::Write for ArrayBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let space_left = N - self.1;
        if space_left < bytes.len() {
            return Err(fmt::Error);
        }

        self.0[self.1..self.1 + bytes.len()].copy_from_slice(bytes);
        self.1 += bytes.len();
        Ok(())
    }
}

struct ExpectedByDisplay<T>(T);
impl<T: fmt::Display> de::Expected for ExpectedByDisplay<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// For defaulting a field to `true`.
pub fn default_to_true() -> bool {
    true
}

/// For skipping field serialization if it's set to `true`.
///
/// (Use with `default_to_true()`.
pub fn skip_if_true(b: &bool) -> bool {
    *b
}

#[cfg(feature = "std")]
enum BytesOrStr<'de> {
    Bytes(Cow<'de, [u8]>),
    Str(Cow<'de, str>),
}

#[cfg(feature = "std")]
struct BytesOrStrVisitor;
#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for BytesOrStr<'de> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        d.deserialize_any(BytesOrStrVisitor)
    }
}

#[cfg(feature = "std")]
impl<'de> de::Visitor<'de> for BytesOrStrVisitor {
    type Value = BytesOrStr<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("byte array or string")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<BytesOrStr<'de>, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut bytes = Vec::new();

        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        Ok(BytesOrStr::Bytes(Cow::Owned(bytes)))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<BytesOrStr<'de>, E>
    where
        E: de::Error,
    {
        Ok(BytesOrStr::Bytes(Cow::Owned(v.to_vec())))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<BytesOrStr<'de>, E>
    where
        E: de::Error,
    {
        Ok(BytesOrStr::Bytes(Cow::Owned(v)))
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<BytesOrStr<'de>, E>
    where
        E: de::Error,
    {
        Ok(BytesOrStr::Bytes(Cow::Borrowed(v)))
    }

    fn visit_str<E>(self, v: &str) -> Result<BytesOrStr<'de>, E>
    where
        E: de::Error,
    {
        Ok(BytesOrStr::Str(Cow::Owned(v.to_string())))
    }

    fn visit_string<E>(self, v: String) -> Result<BytesOrStr<'de>, E>
    where
        E: de::Error,
    {
        Ok(BytesOrStr::Str(Cow::Owned(v)))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<BytesOrStr<'de>, E>
    where
        E: de::Error,
    {
        Ok(BytesOrStr::Str(Cow::Borrowed(v)))
    }
}

/// For deserializing a `Vec<u8>` from either a string or a sequence of bytes.
#[cfg(feature = "std")]
pub fn de_bytestring<'de, D, B>(d: D) -> Result<B, D::Error>
where
    D: Deserializer<'de>,
    B: TryFrom<Vec<u8>>,
{
    match BytesOrStr::deserialize(d)? {
        BytesOrStr::Bytes(b) => b.into_owned(),
        BytesOrStr::Str(s) => s.into_owned().into_bytes(),
    }
    .try_into()
    .map_err(|_| {
        de::Error::custom(format_args!(
            "could not covert to {}",
            type_name::<B>()
        ))
    })
}

/// For serializing a `Vec<u8>` as a bytestring.
pub fn se_bytestring<S>(
    bytes: &impl AsRef<[u8]>,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = bytes.as_ref();
    if s.is_human_readable() {
        match core::str::from_utf8(bytes) {
            Ok(utf8) => s.serialize_str(utf8),
            _ => s.serialize_bytes(bytes),
        }
    } else {
        s.serialize_bytes(bytes)
    }
}

/// Like `se_bytestring` but for use with `#[serde(with)]`.
#[cfg(feature = "std")]
pub mod bytestring {
    pub use super::de_bytestring as deserialize;
    pub use super::se_bytestring as serialize;
}

#[cfg(feature = "std")]
fn hex_to_bytes<B: TryFrom<Vec<u8>>, E: de::Error>(
    bors: BytesOrStr,
) -> Result<B, E> {
    let try_fail = || {
        de::Error::custom(format_args!(
            "could not convert to {}",
            type_name::<B>()
        ))
    };

    let hex = match bors {
        BytesOrStr::Bytes(b) => {
            return b.into_owned().try_into().map_err(|_| try_fail())
        }
        BytesOrStr::Str(s) => s,
    };
    let hex = hex.as_ref();

    if hex.len() % 2 != 0 {
        return Err(de::Error::invalid_length(
            hex.len(),
            &"even-numbered length",
        ));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut byte = 0;
    for (i, digit) in hex.chars().enumerate() {
        byte <<= 4;
        byte |= match digit {
            '0'..='9' => digit as u8 - b'0',
            'a'..='f' => digit as u8 - b'a' + 0xa,
            'A'..='F' => digit as u8 - b'A' + 0xA,
            _ => {
                return Err(de::Error::invalid_value(
                    de::Unexpected::Char(digit),
                    &"hex digit",
                ));
            }
        };
        if i % 2 == 1 {
            bytes.push(byte)
        }
    }

    bytes.try_into().map_err(|_| try_fail())
}

/// For deserializing a `Vec<u8>` from either a string of hex digits or a
/// sequence of bytes.
#[cfg(feature = "std")]
pub fn de_hexstring<'de, D, B>(d: D) -> Result<B, D::Error>
where
    D: Deserializer<'de>,
    B: TryFrom<Vec<u8>>,
{
    hex_to_bytes::<B, D::Error>(BytesOrStr::deserialize(d)?)
}

/// For deserializing a `Vec<Vec<u8>>` from either a string of hex digits or a
/// sequence of bytes.
#[cfg(feature = "std")]
pub fn de_hexstrings<'de, D, B>(d: D) -> Result<Box<[B]>, D::Error>
where
    D: Deserializer<'de>,
    B: TryFrom<Vec<u8>>,
{
    let hexen = Vec::<BytesOrStr>::deserialize(d)?;
    let mut bufs = Vec::with_capacity(hexen.len());
    for hex in hexen {
        bufs.push(hex_to_bytes::<B, D::Error>(hex)?);
    }
    Ok(bufs.into_boxed_slice())
}

/// For serializing a `Vec<u8>` as a hexstring.
#[cfg(feature = "std")]
pub fn se_hexstring<S>(
    bytes: &impl AsRef<[u8]>,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = bytes.as_ref();
    if s.is_human_readable() {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(output, "{:02x}", byte);
        }
        s.serialize_str(&output)
    } else {
        s.serialize_bytes(bytes)
    }
}

/// For serializing a `Vec<u8>` as a hexstring.
#[cfg(not(feature = "std"))]
pub fn se_hexstring<S>(
    bytes: &impl AsRef<[u8]>,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = bytes.as_ref();
    // To serialize a string, serde only provides `serialize_str`, which takes
    // an &str param, rather than exposing a writer-like interface like
    // sequence serialization does.
    //
    // Because we would need to allocate double the space to serialize `bytes`,
    // as opposed to the simple transmutation for `se_bytestring()`, we have to
    // fall back on "just" a byte serialization when in `no_std` mode.
    s.serialize_bytes(bytes)
}

/// For deserializing a `Vec<Vec<u8>>` from either a string of hex digits or a
/// sequence of bytes.
pub fn se_hexstrings<S>(
    bytes: &[impl AsRef<[u8]>],
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    #[derive(serde::Serialize)]
    #[serde(transparent)]
    struct HexString<'a>(#[serde(serialize_with = "se_hexstring")] &'a [u8]);

    s.collect_seq(bytes.iter().map(|b| HexString(b.as_ref())))
}

/// Like `se_hexstring` but for use with `#[serde(with)]`.
#[cfg(feature = "std")]
pub mod hexstring {
    pub use super::de_hexstring as deserialize;
    pub use super::se_hexstring as serialize;
}

/// Helper for `de_radix`.
pub struct Radix<T>(PhantomData<T>);

macro_rules! impl_radix {
    ($($ty:ident)*) => {$(
        impl<'de> de::Visitor<'de> for Radix<$ty> {
            type Value = $ty;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "integer between 0 and {}", $ty::MAX)
            }

            fn visit_borrowed_str<E>(self, s: &'de str) -> Result<$ty, E>
                where E: de::Error,
            {
                let int = if s.starts_with("0b") || s.starts_with("0B") {
                    $ty::from_str_radix(&s[2..], 2)
                }
                else if s.starts_with("0o") || s.starts_with("0O") {
                    $ty::from_str_radix(&s[2..], 8)
                }
                else if s.starts_with("0x") || s.starts_with("0X") {
                    $ty::from_str_radix(&s[2..], 16)
                } else {
                    $ty::from_str_radix(s, 10)
                };

                int.map_err(E::custom)
            }

            fn visit_u64<E>(self, n: u64) -> Result<$ty, E>
                where E: de::Error,
            {
                if n <= core::$ty::MAX as u64 {
                    Ok(n as $ty)
                } else {
                    let msg = concat!("integer between 0 and ", stringify!($ty), "::MAX");
                    Err(E::invalid_value(de::Unexpected::Unsigned(n), &msg))
                }
            }
        }
    )*}
}
impl_radix! {
    u8 u16 u32 u64 usize
}

/// Deserializes an integer from either a string (which supports hex encoding)
/// or a normal integer.
///
/// Unfortunately, the way this is implemented breaks non-self-describing
/// formats, but Serde support isn't really intended for that anways.
pub fn de_radix<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    Radix<T>: de::Visitor<'de, Value = T>,
{
    if d.is_human_readable() {
        d.deserialize_any(Radix::<T>(PhantomData))
    } else {
        d.deserialize_u64(Radix::<T>(PhantomData))
    }
}

/// Like `de_radix` but for use with `#[serde(with)]`.
pub mod dec {
    pub use super::de_radix as deserialize;

    // We cannot just write `use serde::Serialize::serialize;`, so we need to
    // do this silliness instead.
    pub fn serialize<S, X>(x: &X, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        X: serde::Serialize,
    {
        x.serialize(s)
    }
}

/// Serializes an integer as hex.
///
/// This function requires `std` due to what are (apparently?) serde limitations.
pub fn se_hex<S, X>(x: &X, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    X: LowerHex + Into<u64> + Copy,
{
    if s.is_human_readable() {
        let mut buf = ArrayBuf::<18>::default();
        let _ = write!(buf, "{:#01$x}", x, mem::size_of::<X>() * 2 + 2);
        s.serialize_str(buf.as_ref())
    } else {
        s.serialize_u64(x.clone().into())
    }
}

/// Like `se_hex` but for use with `#[serde(with)]`.
pub mod hex {
    pub use super::de_radix as deserialize;
    pub use super::se_hex as serialize;
}

/// Serializes an integer as binary.
///
/// This function requires `std` due to what are (apparently?) serde limitations.
pub fn se_bin<S, X>(x: &X, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    X: Binary + Into<u64> + Copy,
{
    if s.is_human_readable() {
        let mut buf = ArrayBuf::<66>::default();
        let _ = write!(buf, "{:#01$b}", x, mem::size_of::<X>() * 8 + 2);
        s.serialize_str(buf.as_ref())
    } else {
        s.serialize_u64(x.clone().into())
    }
}

/// Like `se_bin` but for use with `#[serde(with)]`.
pub mod bin {
    pub use super::de_radix as deserialize;
    pub use super::se_bin as serialize;
}
