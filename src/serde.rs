// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Internal `serde` helpers.

#![allow(clippy::from_str_radix_10)]

use core::fmt;
use core::fmt::Binary;
use core::fmt::LowerHex;
use core::marker::PhantomData;

#[cfg(feature = "std")]
use std::ffi::CString;

use serde::de;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serializer;

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

/// For deserializing a `Vec<u8>` from either a string or a sequence of bytes.
#[cfg(feature = "std")]
pub fn de_bytestring<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    // CString "does the right thing" per serde's implementation.
    Ok(CString::deserialize(d)?.into_bytes())
}

/// For serializing a `Vec<u8>` as a bytestring.
#[cfg(feature = "std")]
pub fn se_bytestring<S>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(bytes)
}

/// For deserializing an `&[u8; N]`.
pub fn de_u8_array_ref<'de: 'a, 'a, D: Deserializer<'de>, const N: usize>(
    d: D,
) -> Result<&'a [u8; N], D::Error> {
    use core::convert::TryInto as _;

    let slice: &'a [u8] = Deserialize::deserialize(d)?;
    slice.try_into().map_err(|_| {
        <D::Error as serde::de::Error>::invalid_length(
            slice.len(),
            &ExpectedByDisplay(N),
        )
    })
}

/// For deserializing an `&[[u8; N]]`.
pub fn de_slice_of_u8_arrays<
    'de: 'a,
    'a,
    D: Deserializer<'de>,
    const N: usize,
>(
    d: D,
) -> Result<&'a [[u8; N]], D::Error> {
    let slice: &'a [u8] = Deserialize::deserialize(d)?;
    let lv = zerocopy::LayoutVerified::new_slice(slice).ok_or_else(|| {
        <D::Error as serde::de::Error>::invalid_length(
            slice.len(),
            &ExpectedByDisplay(format_args!("multiple of {}", N)),
        )
    })?;
    Ok(lv.into_slice())
}

/// Helper for `de_radix`.
pub struct Radix<T>(PhantomData<T>);

macro_rules! impl_radix {
    ($($ty:ident)*) => {$(
        impl<'de> de::Visitor<'de> for Radix<$ty> {
            type Value = $ty;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "integer between 0 and {}", core::$ty::MAX)
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
    d.deserialize_any(Radix::<T>(PhantomData))
}

/// Serializes an integer as hex.
///
/// This function requires `std` due to what are (apparently?) serde limitations.
#[cfg(feature = "std")]
pub fn se_hex<S, X>(x: X, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    X: LowerHex,
{
    s.serialize_str(&format!("0x{:x}", x))
}

/// Serializes an integer as binary.
///
/// This function requires `std` due to what are (apparently?) serde limitations.
#[cfg(feature = "std")]
pub fn se_bin<S, X>(x: X, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    X: Binary,
{
    s.serialize_str(&format!("0b{:b}", x))
}
