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
