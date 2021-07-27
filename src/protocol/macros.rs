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
        value: $ty:ident $({ $($field:ident: $field_val:expr),* $(,)? })?,
    },)+) => {$(
        #[test]
        fn $name() {
            use $crate::protocol::wire::*;
            use $crate::io::*;
            use $crate::mem::*;
            const BUF_LEN: usize = 1 << 10;

            let bytes: &[u8] = $bytes;
            let value: $ty = $ty $({ $($field: $field_val,)* })?;

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

/// Convenience trait for use with `make_fuzz_safe`.
#[doc(hidden)]
#[cfg(feature = "arbitrary-derive")]
pub trait FuzzSafe {
    type Safe: libfuzzer_sys::arbitrary::Arbitrary;
}

/// Convenience macro for generating a "fuzz-safe" version of the struct that
/// can be cheaply converted into the original struct.
macro_rules! make_fuzz_safe {
    ($name:ident) => {
        #[cfg(feature = "arbitrary-derive")]
        impl $crate::protocol::macros::FuzzSafe for $name {
            type Safe = $name;
        }
    };
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
        impl<$($lt)?> $crate::protocol::macros::FuzzSafe for $name<$($lt)?> {
            type Safe = $wrapper_name;
        }

        #[cfg(feature = "arbitrary-derive")]
        impl $crate::protocol::wire::ToWire for $wrapper_name {
            fn to_wire<W: $crate::io::Write>(&self, w: W)
                -> Result<(), $crate::protocol::wire::Error> {
                $crate::protocol::wire::ToWire::to_wire(&$name {$(
                    $field: make_fuzz_safe!(@extract_ty,
                                            self.$field: $field_ty),
                )*}, w)
            }
        }
    };
    (@convert_ty, (&$lt:tt [$ty:ty])) => {std::boxed::Box<[$ty]>};
    (@convert_ty, (&$lt:tt str)) => {std::boxed::Box<str>};
    (@convert_ty, (&$lt:tt $ty:ty)) => {$ty};
    (@convert_ty, $ty:ty) => {$ty};
    (@extract_ty, $s:tt.$f:tt: (&$lt:lifetime $ty:ty)) => {&$s.$f};
    (@extract_ty, $s:tt.$f:tt: $ty:ty) => {$s.$f};
}
