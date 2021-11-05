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
/// It can also generate tests to ensure that it can be serialized to a JSON
/// string and back again.
///
/// Syntax:
/// ```text
/// rount_trip_test! {
///     test_name: {
///         bytes: <constant expression of type &[u8]>,
///         json: <constant expression of type &str>,
///         value: <struct initializer for the corresponding protocol value>,
///     }
///     // more cases ...
/// }
/// ```
#[cfg(test)]
macro_rules! round_trip_test {
    ($($name:ident: {
        bytes: $bytes:expr,
        json: $json:expr,
        value: $ty:ident$(::$variant:ident)? $({ $($field:ident: $field_val:expr),* $(,)? })?,
    },)+) => {paste::paste!{$(
        #[test]
        fn [<$name _from_wire>]() {
            use $crate::protocol::wire::*;

            let arena = $crate::mem::BumpArena::new(vec![0u8; 4096]);

            let mut bytes_reader: &[u8] = $bytes;
            let from_wire = $ty::from_wire(&mut bytes_reader, &arena).unwrap();

            assert!(bytes_reader.is_empty(), "expected bytes to be fully read");
            pretty_assertions::assert_eq!(from_wire, $ty$(::$variant)? $({ $($field: $field_val,)* })?);
        }

        #[test]
        fn [<$name _to_wire>]() {
            use $crate::protocol::wire::*;

            let mut buf = vec![0u8; 4096];
            let mut cursor = $crate::io::Cursor::new(&mut buf);

            let value = $ty$(::$variant)? $({ $($field: $field_val,)* })?;
            value.to_wire(&mut cursor).expect("serialization failed");

            let bytes: &[u8] = $bytes;
            pretty_assertions::assert_eq!(cursor.consumed_bytes(), bytes);
        }

        #[test]
        fn [<$name _from_json>]() {
            use $crate::protocol::borrowed::*;

            let from_json = serde_json::from_str::<AsStatic::<$ty>>($json).unwrap();
            let from_json: $ty = Borrowed::borrow(&from_json);
            pretty_assertions::assert_eq!(from_json, $ty$(::$variant)? $({ $($field: $field_val,)* })?);
        }

        #[test]
        fn [<$name _to_json>]() {
            let value = $ty$(::$variant)? $({ $($field: $field_val,)* })?;
            let to_json = serde_json::to_string(&value).unwrap();

            let want: serde_json::Value = serde_json::from_str($json).unwrap();
            let got: serde_json::Value = serde_json::from_str(&to_json).unwrap();
            pretty_assertions::assert_eq!(got, want);
        }
    )+}}
}
