// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{borrow::Borrow, iter::zip, mem};

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};

use crate::prime::BigUintPrime;

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

// Returns the inverse of a_u mod m_u (if it exists)
pub fn mod_inverse(a_u: &BigUint, m_u: &BigUint) -> Option<BigUint> {
    if m_u.is_zero() {
        return None;
    }
    let m = BigInt::from_biguint(Sign::Plus, m_u.clone());
    let mut t = (BigInt::zero(), BigInt::one());
    let mut r = (m.clone(), BigInt::from_biguint(Sign::Plus, a_u.clone()));
    while !r.1.is_zero() {
        let q = r.0.clone() / r.1.clone();
        //https://docs.rs/num-integer/0.1.45/src/num_integer/lib.rs.html#353
        let f = |mut r: (BigInt, BigInt)| {
            mem::swap(&mut r.0, &mut r.1);
            r.1 -= q.clone() * r.0.clone();
            r
        };
        r = f(r);
        t = f(t);
    }
    if r.0.is_one() {
        if t.0 < BigInt::zero() {
            return Some((t.0 + m).magnitude().clone());
        }
        return Some(t.0.magnitude().clone());
    }

    None
}

pub fn get_single_coefficient(xs: &[BigUint], i: &BigUint, q: &BigUintPrime) -> BigUint {
    xs.iter()
        .filter(|&l| l != i)
        .map(|l| {
            let l_minus_i = q.subtract_group_elem(l, i);
            //The unwrap is justified as l-i != 0 -> inverse always exists
            #[allow(clippy::unwrap_used)]
            let inv_l_minus_i = mod_inverse(&l_minus_i, q.as_ref()).unwrap();
            l * inv_l_minus_i
        })
        .fold(BigUint::one(), |mut acc, s| {
            acc *= s;
            acc % q.as_ref()
        })
}

// Computes the lagrange coefficients mod q
fn get_lagrange_coefficient(xs: &[BigUint], q: &BigUintPrime) -> Vec<BigUint> {
    let mut coeffs = vec![];
    for i in xs {
        let w_i = get_single_coefficient(xs, i, q);
        coeffs.push(w_i);
    }
    coeffs
}

/// Computes the lagrange interpolation in the field Z_q
/// The arguments are
/// - xs - the list of nodes, field elements in Z_q
/// - ys - the list of values, field elements in Z_q
/// - q - field modulus
pub fn field_lagrange_at_zero(xs: &[BigUint], ys: &[BigUint], q: &BigUintPrime) -> BigUint {
    let coeffs = get_lagrange_coefficient(xs, q);
    zip(coeffs, ys)
        .map(|(c, y)| c * y % q.as_ref())
        .fold(BigUint::zero(), |mut acc, s| {
            acc += s;
            acc % q.as_ref()
        })
}

/// Computes the lagrange interpolation in the exponent of group element.
/// The arguments are
/// - xs - the list of nodes, field elements in Z_q
/// - ys - the list of values (in the exponent), group elements in Z-p^r
/// - q - field modulus
/// - p - group modulus
pub fn group_lagrange_at_zero(
    xs: &[BigUint],
    ys: &[BigUint],
    q: &BigUintPrime,
    p: &BigUintPrime,
) -> BigUint {
    let coeffs = get_lagrange_coefficient(xs, q);
    zip(coeffs, ys)
        .map(|(c, y)| y.modpow(&c, p.as_ref()))
        .fold(BigUint::one(), |mut acc, s| {
            acc *= s;
            acc % p.as_ref()
        })
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

    #[test]
    fn test_mod_inverse() {
        assert_eq!(
            mod_inverse(&BigUint::from(3_u8), &BigUint::from(11_u8)),
            Some(BigUint::from(4_u8)),
            "The inverse of 3 mod 11 should be 4."
        );
        assert_eq!(
            mod_inverse(&BigUint::from(0_u8), &BigUint::from(11_u8)),
            None,
            "The inverse of 0 mod 11 should not exist."
        );
        assert_eq!(
            mod_inverse(&BigUint::from(3_u8), &BigUint::from(12_u8)),
            None,
            "The inverse of 3 mod 12 should not exist."
        )
    }

    #[test]
    fn test_lagrange_interpolation() {
        // Toy parameters according to specs
        let q = BigUintPrime::new_unchecked_the_caller_guarantees_that_this_number_is_prime(
            BigUint::from(127_u8),
        );
        let p = BigUintPrime::new_unchecked_the_caller_guarantees_that_this_number_is_prime(
            BigUint::from(59183_u32),
        );
        let g = BigUint::from(32616_u32);
        // Test polynomial x^2 -1
        let xs = [
            BigUint::from(1_u8),
            BigUint::from(2_u8),
            BigUint::from(3_u8),
        ];
        let ys = [
            BigUint::from(0_u8),
            BigUint::from(3_u8),
            BigUint::from(8_u8),
        ];
        let group_ys: Vec<_> = ys.iter().map(|x| g.modpow(x, p.as_ref())).collect();
        // -1 mod q
        let x_0 = BigUint::from(126_u8);

        assert_eq!(field_lagrange_at_zero(&xs, &ys, &q), x_0);
        assert_eq!(
            group_lagrange_at_zero(&xs, &group_ys, &q, &p),
            g.modpow(&x_0, p.as_ref())
        )
    }
}
