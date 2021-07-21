// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! DER parser tests.
//!
//! These are hung off to the side to avoid cluttering the main der.rs.

// NOTE: This is only for convenience and should be avoided in non-test code.
use untrusted::{Input, Reader};

use crate::cert::testdata;
use crate::cert::x509::der;
use crate::cert::x509::der::Tag;
use crate::cert::Error::BadEncoding;

type Result = core::result::Result<(), crate::cert::Error>;

#[test]
fn long_form_tag() {
    let mut tag = Reader::new(testdata::LONG_FORM_TAG);
    assert!(Tag::parse(&mut tag).is_err());
}

#[test]
fn context_tag() {
    assert_eq!(Tag::context_specific(3), Tag(0b10_1_00011));
}

// NOTE: We don't test der::any very much, since it's tested indirectly by all
// of the helpers.
#[test]
fn short_form_any() -> Result {
    testdata::SHORT_FORM_ANY.read_all(BadEncoding, |buf| {
        let (tag, body) = der::any(buf)?;
        assert_eq!(tag, Tag::SEQUENCE);
        body.read_all(BadEncoding, |buf| {
            let (tag, body) = der::any(buf)?;
            assert_eq!(tag, Tag::INTEGER);
            assert_eq!(body.as_slice_less_safe(), [42]);
            Ok(())
        })
    })
}

#[test]
fn long_form_any() {
    let mut reader = Reader::new(testdata::LONG_FORM_ANY);
    assert!(der::any(&mut reader).is_err());
}

#[test]
fn indefinite_any() {
    let mut reader = Reader::new(testdata::INDEFINITE_ANY);
    assert!(der::any(&mut reader).is_err());
}

#[test]
fn opt_present() -> Result {
    testdata::NULL.read_all(BadEncoding, |buf| {
        let body = der::opt(Tag::NULL, buf)?;
        assert!(body.unwrap().is_empty());
        Ok(())
    })
}

#[test]
fn opt_missing() -> Result {
    testdata::EMPTY.read_all(BadEncoding, |buf| {
        assert!(der::opt(Tag::NULL, buf)?.is_none());
        Ok(())
    })
}

#[test]
fn opt_wrong() -> Result {
    testdata::FORTY_TWO.read_all(BadEncoding, |buf| {
        assert!(der::opt(Tag::NULL, buf)?.is_none());
        assert!(der::opt(Tag::INTEGER, buf)?.is_some());
        Ok(())
    })
}

#[test]
fn parse_right() -> Result {
    testdata::FORTY_TWO.read_all(BadEncoding, |buf| {
        let body = der::parse(Tag::INTEGER, buf)?;
        assert_eq!(body.as_slice_less_safe(), [42]);
        Ok(())
    })
}

#[test]
fn parse_wrong() {
    let mut reader = Reader::new(testdata::NULL);
    assert!(der::parse(Tag::INTEGER, &mut reader).is_err());
}

#[test]
fn tagged() -> Result {
    testdata::SHORT_FORM_ANY.read_all(BadEncoding, |buf| {
        der::tagged(Tag::SEQUENCE, buf, |buf| {
            let body = der::parse(Tag::INTEGER, buf)?;
            assert_eq!(body.as_slice_less_safe(), [42]);
            Ok(())
        })
    })
}

#[test]
fn bits_total() -> Result {
    testdata::BITS_TOTAL.read_all(BadEncoding, |buf| {
        let bits = der::bits_total(buf)?;
        assert_eq!(bits.as_slice_less_safe(), [0xaa, 0xaa]);
        Ok(())
    })
}

#[test]
fn bits_total_wrong_tag() {
    let mut reader = Reader::new(testdata::FORTY_TWO);
    assert!(der::bits_total(&mut reader).is_err());
}

#[test]
fn bits_total_padded() {
    let mut reader = Reader::new(testdata::BITS_PARTIAL);
    assert!(der::bits_total(&mut reader).is_err());
}

#[test]
fn bits_total_overflow() {
    let mut reader = Reader::new(testdata::BITS_OVERFLOW);
    assert!(der::bits_total(&mut reader).is_err());
}

#[test]
fn bits_partial_actually_total() -> Result {
    testdata::BITS_TOTAL.read_all(BadEncoding, |buf| {
        let bits = der::bits_partial(buf)?;
        assert_eq!(bits.as_slice_less_safe(), [0xaa, 0xaa]);
        Ok(())
    })
}

#[test]
fn bits_partial_actually_partial() -> Result {
    testdata::BITS_PARTIAL.read_all(BadEncoding, |buf| {
        let bits = der::bits_partial(buf)?;
        assert_eq!(bits.as_slice_less_safe(), [0xaa, 0xa8]);
        Ok(())
    })
}

#[test]
fn bits_partial_wrong_tag() {
    let mut reader = Reader::new(testdata::FORTY_TWO);
    assert!(der::bits_partial(&mut reader).is_err());
}

#[test]
fn bits_partial_bad_padding() {
    let mut reader = Reader::new(testdata::BITS_PARTIAL_BAD);
    assert!(der::bits_partial(&mut reader).is_err());
}

#[test]
fn bits_partial_overflow() {
    let mut reader = Reader::new(testdata::BITS_OVERFLOW);
    assert!(der::bits_partial(&mut reader).is_err());
}

#[test]
fn uint_0() -> Result {
    testdata::ZERO.read_all(BadEncoding, |buf| {
        let int = der::uint(buf)?;
        assert_eq!(int.as_slice_less_safe(), [0]);
        Ok(())
    })
}

#[test]
fn uint_42() -> Result {
    testdata::FORTY_TWO.read_all(BadEncoding, |buf| {
        let int = der::uint(buf)?;
        assert_eq!(int.as_slice_less_safe(), [42]);
        Ok(())
    })
}

#[test]
fn uint_128() -> Result {
    testdata::ONE_TWENTY_EIGHT.read_all(BadEncoding, |buf| {
        let int = der::uint(buf)?;
        assert_eq!(int.as_slice_less_safe(), [00, 128]);
        Ok(())
    })
}

#[test]
fn uint_9000() -> Result {
    testdata::NINE_THOUSAND.read_all(BadEncoding, |buf| {
        let int = der::uint(buf)?;
        assert_eq!(int.as_slice_less_safe(), [0x23, 0x28]);
        Ok(())
    })
}

#[test]
fn uint_huge() -> Result {
    testdata::HUGE_INT.read_all(BadEncoding, |buf| {
        let int = der::uint(buf)?;
        assert_eq!(int.as_slice_less_safe(), [0x55; 5]);
        Ok(())
    })
}

#[test]
fn uint_00() {
    let mut reader = Reader::new(testdata::DOUBLE_ZERO);
    assert!(der::uint(&mut reader).is_err());
}

#[test]
fn uint_neg() {
    let mut reader = Reader::new(testdata::NEGATIVE);
    assert!(der::uint(&mut reader).is_err());
}

#[test]
fn u32_0() -> Result {
    testdata::ZERO.read_all(BadEncoding, |buf| {
        assert_eq!(der::u32(buf)?, 0);
        Ok(())
    })
}

#[test]
fn u32_42() -> Result {
    testdata::FORTY_TWO.read_all(BadEncoding, |buf| {
        assert_eq!(der::u32(buf)?, 42);
        Ok(())
    })
}

#[test]
fn u32_128() -> Result {
    testdata::ONE_TWENTY_EIGHT.read_all(BadEncoding, |buf| {
        assert_eq!(der::u32(buf)?, 128);
        Ok(())
    })
}

#[test]
fn u32_9000() -> Result {
    testdata::NINE_THOUSAND.read_all(BadEncoding, |buf| {
        assert_eq!(der::u32(buf)?, 9000);
        Ok(())
    })
}

#[test]
fn u32_huge() {
    let mut reader = Reader::new(testdata::HUGE_INT);
    assert!(der::u32(&mut reader).is_err());
}

#[test]
fn u32_00() {
    let mut reader = Reader::new(testdata::DOUBLE_ZERO);
    assert!(der::u32(&mut reader).is_err());
}

#[test]
fn u32_neg() {
    let mut reader = Reader::new(testdata::NEGATIVE);
    assert!(der::u32(&mut reader).is_err());
}

#[test]
fn null() -> Result {
    testdata::NULL.read_all(BadEncoding, der::null)
}

#[test]
fn null_bad_tag() {
    let mut reader = Reader::new(testdata::FORTY_TWO);
    assert!(der::null(&mut reader).is_err());
}

#[test]
fn null_nonempty() {
    let mut reader = Reader::new(testdata::NONEMPTY_NULL);
    assert!(der::null(&mut reader).is_err());
}

#[test]
fn opt_bool_true() -> Result {
    testdata::TRUE.read_all(BadEncoding, |buf| {
        assert_eq!(der::opt_bool(buf)?, Some(true));
        Ok(())
    })
}

#[test]
fn opt_bool_false() -> Result {
    testdata::FALSE.read_all(BadEncoding, |buf| {
        assert_eq!(der::opt_bool(buf)?, Some(false));
        Ok(())
    })
}
#[test]
fn opt_bool_wrong_tag() -> Result {
    testdata::FORTY_TWO.read_all(BadEncoding, |buf| {
        assert!(der::opt_bool(buf)?.is_none());
        buf.skip_to_end();
        Ok(())
    })
}

#[test]
fn opt_bool_empty() -> Result {
    testdata::EMPTY.read_all(BadEncoding, |buf| {
        assert!(der::opt_bool(buf)?.is_none());
        Ok(())
    })
}

#[test]
fn opt_bool_bad() {
    let mut reader = Reader::new(testdata::BAD_BOOL);
    assert!(der::opt_bool(&mut reader).is_err());
}
