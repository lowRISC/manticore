// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Wire format traits.
//!
//! This module provides [`FromWire`] and [`ToWire`], a pair of traits similar
//! to the core traits in the [`serde`] library. Rather than representing a
//! generically serializeable type, they represent types that can be converted
//! to and from Cerberus's wire format, which has a unique, ad-hoc data model.
//!
//! [`FromWire`]: trait.FromWire.html
//! [`ToWire`]: trait.ToWire.html
//! [`serde`]: https://serde.rs

use crate::io;
use crate::io::LeInt;
use crate::io::Read;
use crate::io::Write;

/// A type which can be deserialized from the Cerberus wire format.
///
/// The lifetime `'wire` indicates that the type can be deserialized from a
/// buffer of lifetime `'wire`.
pub trait FromWire<'wire>: Sized {
    /// Deserializes a `Self` w of `r`.
    fn from_wire<R: Read<'wire>>(r: R) -> Result<Self, FromWireError>;
}

/// An deserialization error.
#[derive(Clone, Copy, Debug)]
pub enum FromWireError {
    /// Indicates that something went wrong in an `io` operation.
    ///
    /// [`io`]: ../../io/index.html
    Io(io::Error),

    /// Indicates that some field within the request was outside of its
    /// valid range.
    OutOfRange,
}

impl From<io::Error> for FromWireError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// A type which can be serialized into the Cerberus wire format.
pub trait ToWire: Sized {
    /// Serializes `self` into `w`.
    fn to_wire<W: Write>(&self, w: W) -> Result<(), ToWireError>;
}

/// A serializerion error.
#[derive(Clone, Copy, Debug)]
pub enum ToWireError {
    /// Indicates that something went wrong in an [`io`] operation.
    ///
    /// [`io`]: ../../io/index.html
    Io(io::Error),
}

impl From<io::Error> for ToWireError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Represents a C-like enum that can be converted to and from a wire
/// representation.
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
pub trait WireEnum: Sized + Copy {
    /// The unrelying "wire type". This is almost always some kind of
    /// unsigned integer.
    type Wire: LeInt;

    /// Converts `self` into its underlying wire representation.
    fn to_wire_value(self) -> Self::Wire;

    /// Attemts to parse a value of `Self` from the underlying wire
    /// representation.
    fn from_wire_value(wire: Self::Wire) -> Option<Self>;
}

impl<'wire, E> FromWire<'wire> for E
where
    E: WireEnum,
{
    fn from_wire<R: Read<'wire>>(mut r: R) -> Result<Self, FromWireError> {
        let wire = <Self as WireEnum>::Wire::read_from(&mut r)?;
        Self::from_wire_value(wire).ok_or(FromWireError::OutOfRange)
    }
}

impl<E> ToWire for E
where
    E: WireEnum,
{
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), ToWireError> {
        self.to_wire_value().write_to(&mut w)?;
        Ok(())
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
        $($(#[$meta_variant:meta])* $variant:ident = $value:literal,)*
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
                self as $wire
            }
            fn from_wire_value(wire: Self::Wire) -> Option<Self> {
                match wire {
                    $(
                        $value => Some(Self::$variant),
                    )*
                    _ => None,
                }
            }
        }
    }
}
