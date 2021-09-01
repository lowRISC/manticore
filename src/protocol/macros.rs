// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Macros for generating protocol-related functions and structs.

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
        value: $ty:ident$(::$variant:ident)? $({ $($field:ident: $field_val:expr),* $(,)? })?,
    },)+) => {$(
        #[test]
        fn $name() {
            use $crate::protocol::wire::*;
            use $crate::io::*;
            use $crate::mem::*;
            const BUF_LEN: usize = 1 << 10;

            let bytes: &[u8] = $bytes;
            let value: $ty = $ty$(::$variant)? $({ $($field: $field_val,)* })?;

            let mut bytes_reader = bytes;
            let arena = BumpArena::new(vec![0u8; BUF_LEN]);
            let deserialized = $ty::from_wire(&mut bytes_reader, &arena)
                .expect("deserialization failed");
            assert_eq!(bytes_reader.len(), 0,
                "expected bytes to be fully read");
            assert_eq!(deserialized, value);

            let mut buf = vec![0u8; BUF_LEN];
            let mut cursor = Cursor::new(&mut buf);
            value.to_wire(&mut cursor).expect("serialization failed");
            assert_eq!(cursor.consumed_bytes(), bytes);
        }
    )+}
}

/// Convenience macro for generating a "fuzz-safe" version of the struct that
/// can be cheaply converted into the original struct.
macro_rules! make_fuzz_safe {
    ($($name:ty),* $(,)?) => {$(
        #[cfg(feature = "arbitrary-derive")]
        impl<'a> $crate::protocol::macros::fuzz::FuzzSafe<'a> for $name {
            type Safe = $name;
            fn from_safe(safe: &'a Self::Safe) -> Self {
                safe.clone()
            }
        }
    )*};
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident<$lt:lifetime> {$(
            $(#[$field_meta:meta])*
            $field_vis:vis $field:ident: $field_ty:ty,
        )*}
    ) => {
        $(#[$meta])*
        $vis struct $name<$lt> {$(
            $(#[$field_meta])*
            $field_vis $field: $field_ty,
        )*}


        #[cfg(feature = "arbitrary-derive")]
        const _: () = paste::paste!{{
            use $crate::protocol::macros::fuzz::FuzzSafe;
            use libfuzzer_sys::arbitrary::Arbitrary;

            $(
                // The type names may include lifetimes, such as
                // &'wire [u8], so we cannot utter them in the struct
                // below. These type aliases give us a workaround for
                // that.
                type [<$field:camel AsSafe>]<$lt> =
                  <$field_ty as FuzzSafe<$lt>>::Safe;
            )*

            #[derive(Clone, Debug, Arbitrary)]
            $vis struct [<$name FuzzSafe>] {
                $($field: [<$field:camel AsSafe>]<'static>,)*
            }
            impl<'a> FuzzSafe<'a> for $name<'a> {
                type Safe = [<$name FuzzSafe>];
                fn from_safe(safe: &'a Self::Safe) -> Self {
                    $name {$(
                        $field: FuzzSafe::from_safe(&safe.$field),
                    )*}
                }
            }
        }};
    };
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident<$lt:lifetime> {$(
            $(#[$variant_meta:meta])*
            $variant:ident $({$(
                $(#[$field_meta:meta])*
                $field:ident: $field_ty:ty,
            )*})?,
        )*}
    ) => {
        $(#[$meta])*
        $vis enum $name<$lt> {$(
            $(#[$variant_meta])*
            $variant $({$(
                $(#[$field_meta])*
                $field: $field_ty,
            )*})?,
        )*}


        #[cfg(feature = "arbitrary-derive")]
        const _: () = paste::paste!{{
            use $crate::protocol::macros::fuzz::FuzzSafe;
            use libfuzzer_sys::arbitrary::Arbitrary;

            $($($(
                // The type names may include lifetimes, such as
                // &'wire [u8], so we cannot utter them in the struct
                // below. These type aliases give us a workaround for
                // that.
                type [<$variant $field:camel AsSafe>]<$lt> =
                  <$field_ty as FuzzSafe<$lt>>::Safe;
            )*)?)*

            #[derive(Clone, Debug, Arbitrary)]
            $vis enum [<$name FuzzSafe>] {$(
                $variant $({
                    $($field: [<$variant $field:camel AsSafe>]<'static>,)*
                })?,
            )*}
            impl<'a> FuzzSafe<'a> for $name<'a> {
                type Safe = [<$name FuzzSafe>];
                fn from_safe(safe: &'a Self::Safe) -> Self {
                    match safe {$(
                        [<$name FuzzSafe>]::$variant $({$($field),*})? =>
                            $name::$variant $({$($field: FuzzSafe::from_safe($field)),*})?,
                    )*}
                }
            }
        }};
    }
}

#[cfg(feature = "arbitrary-derive")]
#[doc(hidden)]
pub mod fuzz {
    use libfuzzer_sys::arbitrary::Arbitrary;

    pub trait FuzzSafe<'a> {
        type Safe: Arbitrary;
        fn from_safe(safe: &'a Self::Safe) -> Self;
    }

    impl<'a, T: Arbitrary> FuzzSafe<'a> for &'a T {
        type Safe = T;
        fn from_safe(safe: &'a T) -> Self {
            safe
        }
    }

    impl<'a, T: Arbitrary> FuzzSafe<'a> for &'a [T] {
        type Safe = Box<[T]>;
        fn from_safe(safe: &'a Box<[T]>) -> Self {
            safe
        }
    }

    impl<'a> FuzzSafe<'a> for &'a str {
        type Safe = Box<str>;
        fn from_safe(safe: &'a Box<str>) -> Self {
            safe
        }
    }

    impl<'a, T: Clone, const N: usize> FuzzSafe<'a> for [T; N]
    where
        Self: Arbitrary,
    {
        type Safe = Self;
        fn from_safe(safe: &'a Self) -> Self {
            safe.clone()
        }
    }

    make_fuzz_safe! {
        u8, u16, u32, u64, u128, usize,
        i8, i16, i32, i64, i128, isize,
        (u8, u8),
    }
}
