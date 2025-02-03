// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use anyhow::{bail, ensure, Result};
use num_bigint::BigUint;

/// Converts a `BigUint` to a string using uppercase hex digits with no prefix.
///
/// `fixed_len_bits` - the result will be padded with leading zeros to the *number of bytes* required
/// to hold the specified number of bits. If the input number is too large, then an error is returned.
pub fn to_string_uppercase_hex_bits(u: &BigUint, fixed_len_bits: u32) -> Result<String> {
    let fixed_len_bits = (fixed_len_bits as u64).max(1);
    let fixed_len_bytes = (fixed_len_bits + 7) / 8;
    let fixed_len_digits = fixed_len_bytes * 2;
    let fixed_len_bits = fixed_len_digits * 4;

    let value_bits = u.bits().max(1);
    ensure!(
        value_bits <= fixed_len_bits,
        "Value of {value_bits} bits is too large for specified fixed length of {fixed_len_bits} bit result."
    );

    let value_digits = (value_bits + 3) / 4;

    let s = if value_digits < fixed_len_digits {
        let prepend_leading = fixed_len_digits - value_digits;
        let leading_zeros = "0".repeat(prepend_leading as usize);
        format!("{leading_zeros}{u:X}")
    } else {
        format!("{u:X}")
    };

    ensure!(
        s.len() as u64 == fixed_len_digits,
        "Output length mismatch. Got {}, expected {fixed_len_digits}",
        s.len()
    );

    Ok(s)
}

/// Converts a `BigUint` to a string using uppercase hex digits with no prefix. Pads with leading
/// zeroes to match the smallest power-of-2 *number of bytes* required to hold the value.
///
/// This heuristic is not appropriate for every situation.
pub fn to_string_uppercase_hex_infer_len(u: &BigUint) -> String {
    let value_bits = u.bits().max(1);
    let value_digits = value_bits.div_ceil(4);
    let value_bytes = value_digits.div_ceil(2);

    let fixed_len_bytes = value_bytes.next_power_of_two();
    let fixed_len_digits = fixed_len_bytes * 2;

    if value_digits < fixed_len_digits {
        let prepend_leading = fixed_len_digits - value_digits;
        let leading_zeros = "0".repeat(prepend_leading as usize);
        format!("{leading_zeros}{u:X}")
    } else {
        format!("{u:X}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod to_string {
    use insta::assert_ron_snapshot;

    use super::*;

    #[test]
    fn fixed_len_specified() {
        fn r<T: Into<BigUint>>(u: T, fixed_len_bits: u32) -> std::result::Result<String, String> {
            let u: BigUint = u.into();
            to_string_uppercase_hex_bits(&u, fixed_len_bits).map_err(|e| e.to_string())
        }

        assert_ron_snapshot!(r(  0x00_u8,  0),  @r###"Ok("00")"###);
        assert_ron_snapshot!(r(  0x01_u8,  1),  @r###"Ok("01")"###);
        assert_ron_snapshot!(r(  0x00_u8,  2),  @r###"Ok("00")"###);
        assert_ron_snapshot!(r(  0x00_u8,  3),  @r###"Ok("00")"###);
        assert_ron_snapshot!(r(  0x00_u8,  4),  @r###"Ok("00")"###);
        assert_ron_snapshot!(r(  0x00_u8,  5),  @r###"Ok("00")"###);
        assert_ron_snapshot!(r(  0x00_u8,  8),  @r###"Ok("00")"###);
        assert_ron_snapshot!(r(  0x0A_u8,  9),  @r###"Ok("000A")"###);
        assert_ron_snapshot!(r( 0x000_u16, 12), @r###"Ok("0000")"###);
        assert_ron_snapshot!(r( 0xABC_u16, 12), @r###"Ok("0ABC")"###);
        assert_ron_snapshot!(r(0x0000_u16, 13), @r###"Ok("0000")"###);
        assert_ron_snapshot!(r(0x0ABC_u16, 13), @r###"Ok("0ABC")"###);
        assert_ron_snapshot!(r(0x0ABC_u16, 15), @r###"Ok("0ABC")"###);
        assert_ron_snapshot!(r(0x0ABC_u16, 16), @r###"Ok("0ABC")"###);
        assert_ron_snapshot!(r(0x0ABC_u16, 17), @r###"Ok("000ABC")"###);
    }

    #[test]
    #[rustfmt::skip]
    #[allow(clippy::unusual_byte_groupings)]
    fn infer_len() {
        fn r(u: u64) -> String {
            let u: BigUint = u.into();
            to_string_uppercase_hex_infer_len(&u)
        }

        assert_ron_snapshot!(r(0x________________00),               @r###""00""###);
        assert_ron_snapshot!(r(0x________________01),               @r###""01""###);
        assert_ron_snapshot!(r(0x________________FF),               @r###""FF""###);
        assert_ron_snapshot!(r(0x________________00),               @r###""00""###);
        assert_ron_snapshot!(r(0x________________00),               @r###""00""###);
        assert_ron_snapshot!(r(0x________________00),               @r###""00""###);
        assert_ron_snapshot!(r(0x________________00),               @r###""00""###);
        assert_ron_snapshot!(r(0x______________0100),             @r###""0100""###);
        assert_ron_snapshot!(r(0x______________FFFF),             @r###""FFFF""###);
        assert_ron_snapshot!(r(0x__________00010000),         @r###""00010000""###);
        assert_ron_snapshot!(r(0x__________FFFFFFFF),         @r###""FFFFFFFF""###);
        assert_ron_snapshot!(r(0x_00000001_00000000), @r###""0000000100000000""###);
        assert_ron_snapshot!(r(0x_FFFFFFFF_FFFFFFFF), @r###""FFFFFFFFFFFFFFFF""###);
    }
}

//-------------------------------------------------------------------------------------------------|

/// Read a `BigUint` number from a string, requiring uppercase hex digits only.
pub fn biguint_from_str_uppercase_hex_bits(s: &str, fixed_len_bits: u32) -> Result<BigUint> {
    let needed_bytes = (fixed_len_bits + 7) / 8;
    let needed_digits = needed_bytes * 2;

    let s_len = s.len();
    let s_len_u64 = s_len as u64;
    ensure!(
        needed_digits as u64 == s_len_u64,
        "Expecting {needed_digits} uppercase hex digits, got {s_len} characters."
    );

    // Iterate the string in reverse, to accumulate the limbs in little-endian order.

    let mut limbs = Vec::<u32>::with_capacity(s.len() / 8 + 1);
    let mut u: u32 = 0;
    let mut next_shift = 0;

    for ch in s.chars().rev() {
        let hexdigit_value = match ch {
            '0'..='9' => ch as u32 - b'0' as u32,
            'A'..='F' => ch as u32 - b'A' as u32 + 10,
            _ => bail!("Invalid character in base16 uppercase number: {}", ch),
        };

        u |= hexdigit_value << next_shift;
        next_shift += 4;

        if next_shift == 32 {
            limbs.push(u);
            u = 0;
            next_shift = 0;
        }
    }

    if u != 0 {
        limbs.push(u);
    }

    // Remove any leading zero limbs.
    #[allow(clippy::unwrap_used)] // Unwrap() is justified here because we check for empty.
    while !limbs.is_empty() && limbs.last().unwrap() == &0 {
        limbs.pop();
    }

    Ok(BigUint::new(limbs))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod from_str {
    use insta::assert_ron_snapshot;

    use super::*;

    fn r(s: &str, fixed_len_bits: u32) -> std::result::Result<String, String> {
        biguint_from_str_uppercase_hex_bits(s, fixed_len_bits)
            .map(|v| {
                let mut s = v.to_str_radix(16);
                s.make_ascii_uppercase();
                s
            })
            .map_err(|e| e.to_string())
    }

    #[test]
    #[rustfmt::skip]
    fn with_prefix() {
        assert_ron_snapshot!(r("",   0), @r###"Ok("0")"###);
        assert_ron_snapshot!(r("00", 0), @r###"Err("Expecting 0 uppercase hex digits, got 2 characters.")"###);
        assert_ron_snapshot!(r("01", 1), @r###"Ok("1")"###);
        assert_ron_snapshot!(r("10", 2), @r###"Ok("10")"###);
        assert_ron_snapshot!(r("03", 7), @r###"Ok("3")"###);
        assert_ron_snapshot!(r("40", 8), @r###"Ok("40")"###);
        assert_ron_snapshot!(r("05", 9), @r###"Err("Expecting 4 uppercase hex digits, got 2 characters.")"###);
        assert_ron_snapshot!(r("00000000 00000000", 64), @r#"Err("Expecting 16 uppercase hex digits, got 17 characters.")"#);
        assert_ron_snapshot!(r("A", 8),  @r#"Err("Expecting 2 uppercase hex digits, got 1 characters.")"#);
        assert_ron_snapshot!(r("A0", 8), @r#"Ok("A0")"#);
        assert_ron_snapshot!(r("FE\tDCB\rA987\n654321 0", 64), @r#"Err("Expecting 16 uppercase hex digits, got 20 characters.")"#);
        assert_ron_snapshot!(r("FEDCBA9876543210", 56), @r#"Err("Expecting 14 uppercase hex digits, got 16 characters.")"#);
        assert_ron_snapshot!(r("FEDCBA9876543210", 57), @r#"Ok("FEDCBA9876543210")"#);
        assert_ron_snapshot!(r("FEDCBA9876543210", 63), @r#"Ok("FEDCBA9876543210")"#);
        assert_ron_snapshot!(r("FEDCBA9876543210", 64), @r#"Ok("FEDCBA9876543210")"#);
        assert_ron_snapshot!(r("FEDCBA9876543210", 64), @r#"Ok("FEDCBA9876543210")"#);
    }
}
