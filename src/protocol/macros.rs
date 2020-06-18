// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Macros for generating protocol-related functions and structs.

/// A conveinence macro for generating `WireEnum`-implementing enums.
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

        impl $crate::protocol::WireEnum for $name {
            type Wire = $wire;
            fn to_wire(self) -> Self::Wire {
                self as $wire
            }
            fn from_wire(wire: Self::Wire) -> Option<Self> {
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

/// A convenience macro for generating `Arbitrary` implementations for
/// staticized versions of `protocol` structs with lifetimes in them.
macro_rules! static_arbitrary {
    (struct $name:ident<'static> in mod $m:ident {
        $($field:ident: $field_ty:ty,)*
    }) => {
        #[cfg(feature = "arbitrary-derive")]
        mod $m {
            use libfuzzer_sys::arbitrary::{self, Arbitrary};
            use super::*;
            #[derive(Arbitrary)]
            struct Bridge { $($field: $field_ty)* }
            impl From<Bridge> for $name<'static> {
                fn from(b: Bridge) -> Self {
                    Self { $($field: b.$field,)* }
                }
            }

            impl Arbitrary for $name<'static> {
                fn arbitrary(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Self> {
                    Bridge::arbitrary(u).map(Self::from)
                }
                fn arbitrary_take_rest(u: arbitrary::Unstructured) -> arbitrary::Result<Self> {
                    Bridge::arbitrary_take_rest(u).map(Self::from)
                }
                fn size_hint(depth: usize) -> (usize, Option<usize>) {
                    Bridge::size_hint(depth)
                }
                fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
                    let b = Bridge { $($field: self.$field.clone())* };
                    Box::new(b.shrink().map(Self::from))
                }
            }
        }
    }
}
