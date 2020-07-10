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

/// Covenience macro for generating a "round trip unit test".
///
/// This macro generates a unit test for a protocol struct that ensures that a
/// given byte slice can be converted back and forth with a given value of a
/// protocol struct, exactly.
///
/// Syntax:
/// ```text
/// rount_trip_test! {
///     test_name: {
///         bytes: <contant expression of type &[u8]>,
///         value: <struct initializer for the corresponding protocol value>,
///     }
///     // more cases ...
/// }
/// ```
#[cfg(test)]
macro_rules! round_trip_test {
    ($($name:ident: {
        bytes: $bytes:expr,
        value: $ty:ident $({ $($field:ident: $field_val:expr),* $(,)? })?,
    },)+) => {$(
        #[test]
        fn $name() {
            use $crate::protocol::*;
            let bytes: &[u8] = $bytes;
            let value: $ty = $ty $({ $($field: $field_val,)* })?;

            let mut bytes_reader = bytes;
            let deserialized = $ty::from_wire(&mut bytes_reader)
                .expect("deserialization failed");
            assert_eq!(bytes_reader.len(), 0,
                "expected bytes to be fully read");
            assert_eq!(deserialized, value);

            const BUF_LEN: usize = 1 << 10;
            let mut buf = [0u8; BUF_LEN];
            let mut buf_ref = &mut buf[..];
            value.to_wire(&mut buf_ref).expect("serialization failed");
            let len = BUF_LEN - buf_ref.len();
            let serialized = &buf[..len];
            assert_eq!(serialized, bytes);
        }
    )+}
}

#[cfg(feature = "arbitrary-derive")]
/// Convenience trait for use with `make_fuzz_safe`.
#[doc(hidden)]
pub trait FuzzSafe {
    type Safe: libfuzzer_sys::arbitrary::Arbitrary;
}

/// Convenience macro for generating a "fuzz-safe" version of the struct that
/// can be cheaply converted into the original struct.
macro_rules! make_fuzz_safe {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident $(<$lt:lifetime>)? as $wrapper_name:ident {$(
            $(#[$field_meta:meta])*
            $field_vis:vis $field:ident:
                // Because we need to destructure on this, this *cannot* be a
                // type. Hence, we accept a token-tree instead, with the
                // understanding that callers will wrap complex types in
                // parentheses.
                //
                // This is a limitation of the macro engine. See
                // https://danielkeep.github.io/tlborm/book/mbe-min-captures-and-expansion-redux.html
            $field_ty:tt,
        )*}
    ) => {
        $(#[$meta])*
        #[allow(unused_parens)]
        $vis struct $name $(<$lt>)? {$(
            $(#[$field_meta])*
            $field_vis $field: $field_ty,
        )*}

        #[cfg(feature = "arbitrary-derive")]
        #[derive(Clone, Debug, Arbitrary)]
        #[allow(unused_parens)]
        #[doc(hidden)]
        $vis struct $wrapper_name {$(
            $field: make_fuzz_safe!(@convert_ty, $field_ty),
        )*}
        #[cfg(feature = "arbitrary-derive")]
        impl $wrapper_name {
            /// Borrow this value into a protocol struct.
            pub fn as_ref<$($lt)?>(&$($lt)? self)
            -> $name<$($lt)?> {
                $name {$(
                    $field: make_fuzz_safe!(@extract_ty,
                                            self.$field: $field_ty),
                )*}
            }
        }
        #[cfg(feature = "arbitrary-derive")]
        impl<$($lt)?> $crate::protocol::macros::FuzzSafe for $name<$($lt)?> {
            type Safe = $wrapper_name;
        }
    };
    (@convert_ty, (&$lt:tt [$ty:ty])) => {std::boxed::Box<[$ty]>};
    (@convert_ty, (&$lt:tt str)) => {std::boxed::Box<str>};
    (@convert_ty, (&$lt:tt $ty:ty)) => {$ty};
    (@convert_ty, $ty:ty) => {$ty};
    (@extract_ty, $s:tt.$f:tt: (&$lt:lifetime $ty:ty)) => {&$s.$f};
    (@extract_ty, $s:tt.$f:tt: $ty:ty) => {$s.$f};
}
