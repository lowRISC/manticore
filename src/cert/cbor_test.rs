// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! CBOR parser tests.
//!
//! These are hung off to the side to avoid cluttering the main der.rs.

#![allow(unused)]

// NOTE: This is only for convenience and should be avoided in non-test code.
use untrusted::Input;

use crate::cert::cbor::Int;
use crate::cert::cbor::Item;
use crate::cert::Error::BadEncoding;

type Result = core::result::Result<(), crate::cert::Error>;

const UINT: u8 = 0;
const NINT: u8 = 1;
const UTF8: u8 = 3;
const BYTES: u8 = 2;
const ARRAY: u8 = 4;
const MAP: u8 = 5;

#[test]
fn bad_tags() -> Result {
    let cbor = raw_cbor! {
        // Non-minimal argument.
        UINT@1:0

        // 64-bit argument.
        UINT@0:27

        // Reserved low bits.
        UINT@0:28
        UINT@0:29
        UINT@0:30

        // Indefinte form.
        ARRAY@0:31

        // Early EOF.
        UINT@0:24
    };

    Input::from(&cbor).read_all(BadEncoding, |buf| {
        assert!(Item::parse(buf).is_err());
        assert!(Item::parse(buf).is_err());
        assert!(Item::parse(buf).is_err());
        assert!(Item::parse(buf).is_err());
        assert!(Item::parse(buf).is_err());
        assert!(Item::parse(buf).is_err());
        assert!(Item::parse(buf).is_err());

        // Make sure that we hit EOF.
        let _ = buf.read_bytes_to_end();
        Ok(())
    })
}

#[test]
fn parse_ints() -> Result {
    let cbor = raw_cbor! {
        UINT:0     // 0
        UINT:25    // 25
        UINT:2000  // 2000
        NINT:0     // -1
        NINT:1999  // -2000
    };

    Input::from(&cbor).read_all(BadEncoding, |buf| {
        assert_eq!(Item::parse(buf)?.into_int()?, Int::from(0));
        assert_eq!(Item::parse(buf)?.into_int()?, Int::from(25));
        assert_eq!(Item::parse(buf)?.into_int()?, Int::from(2000));
        assert_eq!(Item::parse(buf)?.into_int()?, Int::from(-1));
        assert_eq!(Item::parse(buf)?.into_int()?, Int::from(-2000));
        Ok(())
    })
}

#[test]
fn parse_bytes() -> Result {
    let cbor = raw_cbor! {
        UTF8 {"Hello, world!"}
        BYTES {"Behold my works ye mighty, and despair."}
    };

    Input::from(&cbor).read_all(BadEncoding, |buf| {
        assert_eq!(Item::parse(buf)?.into_utf8()?, "Hello, world!");
        assert_eq!(
            Item::parse(buf)?.into_bytes()?,
            b"Behold my works ye mighty, and despair."
        );
        Ok(())
    })
}

#[test]
fn bad_bytes() -> Result {
    let cbor = raw_cbor! {
        // Not UTF-8.
        UTF8 {b"\xffHello, world!"}
        // Prefix too big.
        BYTES:29 "Behold"
    };

    Input::from(&cbor).read_all(BadEncoding, |buf| {
        assert!(Item::parse(buf).is_err());
        assert!(Item::parse(buf).is_err());

        // Make sure that we hit EOF.
        let _ = buf.read_bytes_to_end();
        Ok(())
    })
}

#[test]
fn parse_arrays() -> Result {
    let cbor = raw_cbor! {
        ARRAY []  // Empty array.
        ARRAY [UINT:5, NINT:500]
        ARRAY [ARRAY[UTF8 {"I'm a string!"}, UINT:42]]
    };

    Input::from(&cbor).read_all(BadEncoding, |buf| {
        Item::parse(buf)?
            .into_array()?
            .with(|_| panic!("array should be empty"))?;

        let mut ints = Vec::new();
        Item::parse(buf)?.into_array()?.with(|item| {
            ints.push(item.into_int()?);
            Ok(())
        })?;
        assert_eq!(ints, vec![Int::from(5), Int::from(-501)]);

        Item::parse(buf)?.into_array()?.with(|item| {
            let mut idx = 0;
            item.into_array()?.with(|item| {
                match idx {
                    0 => assert_eq!(item.into_utf8()?, "I'm a string!"),
                    1 => assert_eq!(item.into_int()?, Int::from(42)),
                    _ => panic!("too many items in array"),
                }
                idx += 1;
                Ok(())
            })?;
            assert_eq!(idx, 2);
            Ok(())
        })
    })
}

#[test]
fn parse_maps() -> Result {
    let cbor = raw_cbor! {
        MAP []  // Empty map.
        MAP [
            UINT:2          ARRAY [UINT:42],
            UINT:43         BYTES {"abcdefg"},
            NINT:5          MAP [
                UTF8 {"int"}    UINT:42,
                UTF8 {"array"}  ARRAY [UINT:0, UINT:1, UINT:2],
            ],
            NINT:8          NINT:7,
            UTF8 {"hai"}    UTF8 {"bai"},
            UTF8 {"hola"}   UTF8 {"adiós"},
        ]
    };

    Input::from(&cbor).read_all(BadEncoding, |buf| {
        Item::parse(buf)?
            .into_map()?
            .walk(|w| w.with(|_| panic!("map should be empty")))?;

        Item::parse(buf)?.into_map()?.walk(|w| {
            // Get the array from the front.
            w.must_get(Int::from(2))?.into_array()?.with(|_| Ok(()))?;

            // Int(3) isn't present.
            assert!(w.get(Int::from(3))?.is_none());

            // Skip over two elements.
            assert_eq!(w.must_get(Int::from(-9))?.into_int()?, Int::from(-8));
            eprintln!("a");

            let mut rest = Vec::new();
            w.with(|(k, v)| {
                let k = Item::Scalar(k);
                rest.push((k.into_utf8()?, v.into_utf8()?));
                Ok(())
            })?;
            assert_eq!(rest, [("hai", "bai"), ("hola", "adiós")]);

            Ok(())
        })
    })
}

#[test]
fn out_of_order_map() -> Result {
    let cbor = raw_cbor! {
        MAP [
            NINT:0      UTF8 {"should come second"},
            UINT:1000   UTF8 {"should come first"},
        ]
    };

    Input::from(&cbor).read_all(BadEncoding, |buf| {
        assert!(Item::parse(buf)?
            .into_map()?
            .walk(|w| w.with(|_| Ok(())))
            .is_err());
        let _ = buf.read_bytes_to_end();
        Ok(())
    })
}
