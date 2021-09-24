// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Wire format traits.
//!
//! This module provides [`FromWire`] and [`ToWire`], a pair of traits similar
//! to the core traits in the [`serde`] library. Rather than representing a
//! generically serializeable type, they represent types that can be converted
//! to and from Cerberus's wire format, which has a unique, ad-hoc data model.

use core::fmt;

use crate::io;
use crate::io::endian::LeInt;
use crate::io::ReadZero;
use crate::io::Write;
use crate::mem::Arena;
use crate::mem::OutOfMemory;

/// A type which can be deserialized from the Cerberus wire format.
///
/// The lifetime `'wire` indicates that the type can be deserialized from a
/// buffer of lifetime `'wire`.
pub trait FromWire<'wire>: Sized {
    /// Deserializes a `Self` w of `r`.
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        arena: &'wire A,
    ) -> Result<Self, Error>;
}

/// A marshalling error.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Indicates that something went wrong in an `io` operation.
    Io(io::Error),

    /// Indicates that the arena used to allocate dynamic portions of the
    /// deserialization ran out of memory.
    OutOfMemory,

    /// Indicates that some field within the request was outside of its
    /// valid range.
    OutOfRange,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<OutOfMemory> for Error {
    fn from(_: OutOfMemory) -> Self {
        Self::OutOfMemory
    }
}

debug_from!(FromWireError => io::Error, OutOfMemory);

/// A type which can be serialized into the Cerberus wire format.
pub trait ToWire: Sized {
    /// Serializes `self` into `w`.
    fn to_wire<W: Write>(&self, w: W) -> Result<(), Error>;
}

debug_from!(ToWireError => io::Error);

/// Represents a C-like enum that can be converted to and from a wire
/// representation as well as to and from a string representation.
///
/// An implementation of this trait can be thought of as an unsigned
/// integer with a limited range: every enum variant can be converted
/// to the wire format and back, though not every value of the wire
/// representation can be converted into an enum variant.
///
/// In particular the following identity must hold for all types T:
/// ```
/// # use manticore::protocol::wire::WireEnum;
/// # fn test<T: WireEnum + Copy + PartialEq + std::fmt::Debug>(x: T) {
/// assert_eq!(T::from_wire_value(T::to_wire_value(x)), Some(x));
/// # }
/// ```
///
/// Also, the following identity must hold for all types T:
/// ```
/// # use manticore::protocol::wire::WireEnum;
/// # fn test<T: WireEnum + Copy + PartialEq + std::fmt::Debug>(x: T) {
/// assert_eq!(T::from_name(T::name(x)), Some(x));
/// # }
/// ```
pub trait WireEnum: Sized + Copy {
    /// The unrelying "wire type". This is almost always some kind of
    /// unsigned integer.
    type Wire;

    /// Converts `self` into its underlying wire representation.
    fn to_wire_value(self) -> Self::Wire;

    /// Attempts to parse a value of `Self` from the underlying wire
    /// representation.
    fn from_wire_value(wire: Self::Wire) -> Option<Self>;

    /// Converts `self` into a string representation.
    fn name(self) -> &'static str;

    /// Attempts to convert a value of `Self` from a string representation.
    fn from_name(str: &str) -> Option<Self>;
}

impl<'wire, E> FromWire<'wire> for E
where
    E: WireEnum,
    E::Wire: LeInt,
{
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        _: &'wire A,
    ) -> Result<Self, Error> {
        let wire = <Self as WireEnum>::Wire::read_from(r)?;
        Self::from_wire_value(wire).ok_or(Error::OutOfRange)
    }
}

impl<E> ToWire for E
where
    E: WireEnum,
    E::Wire: LeInt,
{
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), Error> {
        self.to_wire_value().write_to(&mut w)?;
        Ok(())
    }
}

/// A deserialization-from-string error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct WireEnumFromStrError;

impl fmt::Display for WireEnumFromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unknown variant")
    }
}

/// A conveinence macro for generating `WireEnum`-implementing enums.
///
///
/// Syntax is as follows:
/// ```text
/// wire_enum! {
///     /// This is my enum.
///     pub enum MyEnum : u8 {
///         /// Variant `A`.
///         A = 0x00,
///         /// Variant `B`.
///         B = 0x01,
///     }
/// }
/// ```
/// This macro will generate an implementation of `WireEnum<Wire=u8>` for
/// the above enum.
macro_rules! wire_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident : $wire:ident {
        $($(#[$meta_variant:meta])* $variant:ident = $value:tt,)*
    }) => {
        $(#[$meta])*
        #[repr($wire)]
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        $vis enum $name {
           $(
               $(#[$meta_variant])*
               $variant = $value,
           )*
        }

        impl $crate::protocol::wire::WireEnum for $name {
            type Wire = $wire;
            fn to_wire_value(self) -> Self::Wire {
                match self {
                    $(
                        Self::$variant => $value,
                    )*
                }
            }
            fn from_wire_value(wire: Self::Wire) -> Option<Self> {
                match wire {
                    $(
                        $value => Some(Self::$variant),
                    )*
                    _ => None,
                }
            }

            fn name(self) -> &'static str {
                match self {
                    $(
                        Self::$variant => stringify!($variant),
                    )*
                }
            }

            fn from_name(name: &str) -> Option<Self> {
                match name {
                    $(
                        stringify!($variant) => Some(Self::$variant),
                    )*
                    _ => None,
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use $crate::protocol::wire::WireEnum;

                write!(f, "{}", self.name())
            }
        }

        impl core::str::FromStr for $name {
            type Err = $crate::protocol::wire::WireEnumFromStrError;

            fn from_str(
                s: &str
            ) -> core::result::Result<
                Self,
                $crate::protocol::wire::WireEnumFromStrError
            > {
                use $crate::protocol::wire::WireEnum;

                match $name::from_name(s) {
                    Some(val) => Ok(val),
                    None => Err($crate::protocol::wire::WireEnumFromStrError),
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    wire_enum! {
        /// An enum for testing.
        pub enum DemoEnum: u8 {
            /// Unknown value
            Unknown = 0x00,

            /// First enum value
            First = 0x01,

            /// Second enum value
            Second = 0x02,
        }
    }

    #[test]
    fn from_name() {
        use crate::protocol::wire::*;

        let value = DemoEnum::from_name("Second").expect("from_name failed");
        assert_eq!(value, DemoEnum::Second);

        let value = DemoEnum::from_name("First").expect("from_name failed");
        assert_eq!(value, DemoEnum::First);

        assert_eq!(None, DemoEnum::from_name("does not exist"));
    }

    #[test]
    fn name() {
        use crate::protocol::wire::*;

        assert_eq!(DemoEnum::First.name(), "First");
        assert_eq!(DemoEnum::Second.name(), "Second");
    }
}
