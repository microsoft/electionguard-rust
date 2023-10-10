// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;

pub fn cnt_bits_repr_usize(n: usize) -> usize {
    if n == 0 {
        1
    } else {
        n.ilog2() as usize + 1
    }
}

//use num_traits::Zero;
pub fn cnt_bits_repr<T: Borrow<BigUint>>(n: &T) -> usize {
    let n: &BigUint = n.borrow();
    if n.is_zero() {
        1
    } else {
        n.bits() as usize
    }
}

pub fn largest_integer_a_such_that_2_to_a_divides_even_n(n: &BigUint) -> u64 {
    assert!(n.is_even(), "requires n even");
    assert!(!n.is_zero(), "requires n > 1");

    // `unwrap()` is justified here because we just verified that 2 <= `n`.
    #[allow(clippy::unwrap_used)]
    n.trailing_zeros().unwrap()
}

// Returns the smallest integer `b` such that `b > a && b | n`.
pub fn round_to_next_multiple(a: usize, x: usize) -> usize {
    if a % x == 0 {
        a
    } else {
        a + (x - (a % x))
    }
}

pub fn to_be_bytes_left_pad<T: Borrow<BigUint>>(n: &T, len: usize) -> Vec<u8> {
    let n: &BigUint = n.borrow();

    let mut v = n.to_bytes_be();

    if v.len() < len {
        let left_pad = len - v.len();
        v.reserve(left_pad);
        v.extend(std::iter::repeat(0).take(left_pad));
        v.rotate_right(left_pad);
    }

    assert!(len <= v.len());

    v
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use num_integer::Integer;

    #[test]
    fn test_cnt_bits_repr_usize() {
        for (n, expected) in [1, 1, 2, 2, 3, 3, 3, 3, 4].into_iter().enumerate() {
            assert_eq!(cnt_bits_repr_usize(n), expected);
            assert_eq!(cnt_bits_repr(&BigUint::from(n)), expected);
        }
    }

    #[test]
    fn test_largest_integer_a_such_that_2_to_a_divides_even_n() {
        for half_n in 1_usize..1000 {
            let n = half_n * 2;

            let a = largest_integer_a_such_that_2_to_a_divides_even_n(&BigUint::from(n));
            assert!(a < 32);
            let two_to_a = 1_usize << a;

            assert!(n.is_multiple_of(&two_to_a));

            for invalid_a in (a + 1)..32 {
                let two_to_invalid_a = 1_usize << invalid_a;
                if n.is_multiple_of(&two_to_invalid_a) {
                    println!("\n\nn={n}, a={a}, invalid_a={invalid_a}, two_to_invalid_a={two_to_invalid_a}\n");
                }
                assert!(!n.is_multiple_of(&two_to_invalid_a));
            }
        }
    }

    #[test]
    fn test_to_be_bytes_left_pad() {
        let x_ff = BigUint::from(0xff_usize);
        assert_eq!(to_be_bytes_left_pad(&x_ff, 0), vec![0xff]);
        assert_eq!(to_be_bytes_left_pad(&x_ff, 1), vec![0xff]);
        assert_eq!(to_be_bytes_left_pad(&x_ff, 2), vec![0x00, 0xff]);
    }
}
