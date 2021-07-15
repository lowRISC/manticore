// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

/// Test-only macro for generating (potentially invalid!) CBOR.
///
/// This macro is defined in this
///
/// Syntax inspired by der-ascii.
macro_rules! raw_cbor {
    (@parse[$out:tt, $count:tt] $ty:tt$(@$len:tt)? {$($tt:tt)*} $($rest:tt)*) => {{
        let inner = raw_cbor!($($tt)*);
        raw_cbor!(@parse[$out, None] $ty$(@$len)?:(inner.len() as u64));
        $out.extend_from_slice(&inner);

        raw_cbor!(@parse[$out, $count] $($rest)*);
    }};
    (@parse[$out:tt, $count:tt] $ty:tt$(@$len:tt)? [] $($rest:tt)*) => {{
        raw_cbor!(@parse[$out, None] $ty$(@$len)?:0);
        raw_cbor!(@parse[$out, $count] $($rest)*);
    }};
    (@parse[$out:tt, $count:tt] $ty:tt$(@$len:tt)? [$($tt:tt)*] $($rest:tt)*) => {{
        let mut inner = Vec::<u8>::new();
        let mut count = 1;
        raw_cbor!(@parse[inner, (Some(&mut count))] $($tt)*);
        raw_cbor!(@parse[$out, None] $ty$(@$len)?:count);
        $out.extend_from_slice(&inner);

        raw_cbor!(@parse[$out, $count] $($rest)*);
    }};
    (@parse[$out:tt, $count:tt] $ty:tt$(@$len:tt)?:$arg:tt $($rest:tt)*) => {{
        use core::convert::TryFrom;

        let mut ty: u8 = $ty;
        assert!(ty < 8);
        ty <<= 5;
        let mut len: Option<u8> = None;
        $(len = Some($len);)?
        let arg: u64 = $arg;

        if let Some(len) = len {
            match len {
                0 => {
                    assert!(arg < 32);
                    $out.push(ty | (arg as u8));
                }
                1 => {
                    assert!(arg <= u8::MAX as u64);
                    $out.push(ty | 24);
                    $out.push(arg as u8);
                }
                2 => {
                    assert!(arg <= u16::MAX as u64);
                    $out.push(ty | 25);
                    $out.extend_from_slice(&(arg as u16).to_be_bytes());
                }
                4 => {
                    assert!(arg <= u32::MAX as u64);
                    $out.push(ty | 26);
                    $out.extend_from_slice(&(arg as u32).to_be_bytes());
                }
                8 => {
                    $out.push(ty | 27);
                    $out.extend_from_slice(&arg.to_be_bytes());
                }
                l => panic!("invalid long-form: {}", l),
            }
        } else {
            if let Ok(arg) = u8::try_from(arg) {
                if arg < 24 {
                    $out.push(ty | arg);
                } else {
                    $out.push(ty | 24);
                    $out.push(arg as u8);
                }
            } else if let Ok(arg) = u16::try_from(arg) {
                $out.push(ty | 25);
                $out.extend_from_slice(&arg.to_be_bytes());
            } else if let Ok(arg) = u32::try_from(arg) {
                $out.push(ty | 26);
                $out.extend_from_slice(&arg.to_be_bytes());
            } else {
                $out.push(ty | 27);
                $out.extend_from_slice(&arg.to_be_bytes());
            }
        }

        raw_cbor!(@parse[$out, $count] $($rest)*);
    }};
    (@parse[$out:tt, $count:tt] ,) => {{
        let _ = $count.unwrap();
    }};
    (@parse[$out:tt, $count:tt] , $($rest:tt)*) => {{
        *$count.unwrap() += 1;
        raw_cbor!(@parse[$out, $count] $($rest)*);
    }};
    (@parse[$out:tt, $count:tt] h$imm:tt $($rest:tt)*) => {{
        let hex: &'static str = $imm;
        let hex: String = hex.chars().filter(|&c| !" \t\r\n".contains(c)).collect();

        assert_eq!(hex.len() % 2, 0);
        for i in (0..hex.len()).step_by(2) {
            $out.push(u8::from_str_radix(&hex[i..i+2], 16).unwrap());
        }

        raw_cbor!(@parse[$out, $count] $($rest)*);
    }};
    (@parse[$out:tt, $count:tt] $imm:tt $($rest:tt)*) => {{
        $out.extend_from_slice($imm.as_ref());
        raw_cbor!(@parse[$out, $count] $($rest)*);
    }};
    (@parse[$out:tt, $count:tt]) => {{}};
    ($($tokens:tt)*) => {{
        let mut out = Vec::<u8>::new();
        #[allow(unused)] let _ = raw_cbor!(@parse[out, None] $($tokens)*);
        out
    }};
}

#[test]
fn test() {
    assert_eq!(raw_cbor!(0:0), [0]);
    assert_eq!(raw_cbor!(1:23), [0b001_10111]);
    assert_eq!(raw_cbor!(1:24), [0b001_11000, 24]);
    assert_eq!(raw_cbor!(1:256), [0b001_11001, 1, 0]);
    assert_eq!(raw_cbor!(1:65536), [0b001_11010, 0, 1, 0, 0]);
    assert_eq!(
        raw_cbor!(1:(1 << 32)),
        [0b001_11011, 0, 0, 0, 1, 0, 0, 0, 0]
    );
    assert_eq!(raw_cbor!(4@2:5), [0b100_11001, 0, 5]);

    assert_eq!(
        raw_cbor!(2 { "hello" }),
        [0b010_00101, b'h', b'e', b'l', b'l', b'o']
    );

    assert_eq!(raw_cbor!(4 []), [0b100_00000]);

    assert_eq!(raw_cbor!(4 ["a", "b",]), [0b100_00010, b'a', b'b'],);
}
