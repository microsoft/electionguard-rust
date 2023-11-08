// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{bail, ensure, Result};
use num_bigint::BigUint;

/// Converts a `BigUint` to a string, prefixed with "base16:" and using uppercase hex digits.
///
/// Currently, `radix` must be 16.
///
/// If `opt_fixed_len_bits` is specified, then the result will be padded with leading zeros to
/// the specified number of bits. If the input number is too large, then an error is returned.
pub fn to_string_with_prefix(
    u: &BigUint,
    radix: usize,
    opt_fixed_len_bits: Option<u32>,
) -> Result<String> {
    match radix {
        16 => to_string_with_prefix_base16(u, opt_fixed_len_bits),
        _ => bail!("Unsupported radix: {radix}"),
    }
}

fn to_string_with_prefix_base16(u: &BigUint, opt_fixed_len_bits: Option<u32>) -> Result<String> {
    let prefix = "base16:";

    let s = if let Some(fixed_len_bits) = opt_fixed_len_bits {
        let fixed_len_bits = (fixed_len_bits as u64).max(1);
        let value_bits = u.bits().max(1);
        ensure!(
            value_bits <= fixed_len_bits,
            "Value of {value_bits} bits too large for specified fixed length, expected {fixed_len_bits} or fewer." );

        let expected_digits = (fixed_len_bits + 3) / 4;
        let value_digits = (value_bits + 3) / 4;

        let s = if value_digits < expected_digits {
            let prepend_leading = expected_digits - value_digits;
            let leading_zeros = "0".repeat(prepend_leading as usize);
            format!("{prefix}{leading_zeros}{u:X}")
        } else {
            format!("{prefix}{u:X}")
        };

        let expected_chars = prefix.len() as u64 + expected_digits;
        ensure!(
            s.len() as u64 == expected_chars,
            "Output length mismatch. Got {}, expected {expected_chars}",
            s.len()
        );

        s
    } else {
        format!("{prefix}{u:X}")
    };

    Ok(s)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod to_string {
    use super::*;
    use insta::assert_ron_snapshot;

    fn r<T: Into<BigUint>>(
        u: T,
        radix: usize,
        opt_fixed_len_bits: Option<u32>,
    ) -> std::result::Result<String, String> {
        let u: BigUint = u.into();
        to_string_with_prefix(&u, radix, opt_fixed_len_bits).map_err(|e| e.to_string())
    }

    #[test]
    fn no_fixed_len() {
        assert_ron_snapshot!(r(0x00_u8, 16, None), @r###"Ok("base16:0")"###);
        assert_ron_snapshot!(r(0xFEDCBA987654321_u64, 16, None), @r###"Ok("base16:FEDCBA987654321")"###);
    }

    #[test]
    fn fixed_len_specified() {
        assert_ron_snapshot!(r(0x00_u8, 16, Some(0)), @r###"Ok("base16:0")"###);
        assert_ron_snapshot!(r(0x01_u8, 16, Some(1)), @r###"Ok("base16:1")"###);
        assert_ron_snapshot!(r(0x00_u8, 16, Some(2)), @r###"Ok("base16:0")"###);
        assert_ron_snapshot!(r(0x00_u8, 16, Some(3)), @r###"Ok("base16:0")"###);
        assert_ron_snapshot!(r(0x00_u8, 16, Some(4)), @r###"Ok("base16:0")"###);
        assert_ron_snapshot!(r(0x00_u8, 16, Some(5)), @r###"Ok("base16:00")"###);
        assert_ron_snapshot!(r(0x00_u8, 16, Some(8)), @r###"Ok("base16:00")"###);
        assert_ron_snapshot!(r(0x0a_u8, 16, Some(9)), @r###"Ok("base16:00A")"###);
        assert_ron_snapshot!(r(0x000_u16, 16, Some(12)), @r###"Ok("base16:000")"###);
        assert_ron_snapshot!(r(0xABC_u16, 16, Some(12)), @r###"Ok("base16:ABC")"###);
        assert_ron_snapshot!(r(0x0000_u16, 16, Some(13)), @r###"Ok("base16:0000")"###);
        assert_ron_snapshot!(r(0x0ABC_u16, 16, Some(13)), @r###"Ok("base16:0ABC")"###);
    }
}

/// Read a `BigUint` number from a string, requiring the prefix "base16:" and uppercase hex digits only.
/// Whitespace is allowed anywhere, except between the characters of the identifier "base16".
pub fn biguint_from_str_with_prefix(s: &str) -> Result<BigUint> {
    // Trim any whitespace and the expected prefix.
    let s = s.trim_start();
    let Some(s) = s.strip_prefix("base16") else {
        bail!("Prefix 'base16' not found on base16 number");
    };
    let s = s.trim_start();
    let Some(s) = s.strip_prefix(':') else {
        bail!("Prefix 'base16:' not found on base16 number");
    };
    let s = s.trim_end();

    // Iterate the string in reverse, to accumulate the limbs in little-endian order.

    let mut limbs = Vec::<u32>::with_capacity(s.len() / 8 + 1);
    let mut u: u32 = 0;
    let mut next_shift = 0;

    for ch in s.chars().rev() {
        let hexdigit_value = match ch {
            '0'..='9' => ch as u32 - b'0' as u32,
            'A'..='F' => ch as u32 - b'A' as u32 + 10,
            ch if ch.is_whitespace() => continue,
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
    use super::*;
    use insta::assert_ron_snapshot;

    fn r(s: &str) -> std::result::Result<String, String> {
        biguint_from_str_with_prefix(s)
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
        assert_ron_snapshot!(r(""),          @r###"Err("Prefix \'base16\' not found on base16 number")"###);
        assert_ron_snapshot!(r("0"),         @r###"Err("Prefix \'base16\' not found on base16 number")"###);
        assert_ron_snapshot!(r(" base16 0"), @r###"Err("Prefix \'base16:\' not found on base16 number")"###);
        assert_ron_snapshot!(r(" base16: 0"),                     @r#"Ok("0")"#);
        assert_ron_snapshot!(r(" base16 : 0000 0000 "),           @r#"Ok("0")"#);
        assert_ron_snapshot!(r("base16:00000000 00000000"),       @r#"Ok("0")"#);
        assert_ron_snapshot!(r("base16:A"),                       @r#"Ok("A")"#);
        assert_ron_snapshot!(r("base16:A0"),                      @r#"Ok("A0")"#);
        assert_ron_snapshot!(r("base16:FE\tDCB\rA987\n654321 0"), @r#"Ok("FEDCBA9876543210")"#);
    }
}
