// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides various utility functions for field and group elements.

use itertools::Itertools;
use std::{borrow::Borrow, collections::HashMap, iter::zip, mem};

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};

use crate::algebra::{FieldElement, Group, GroupElement, ScalarField};

/// Returns the number of bits required to encode the given number.
pub fn cnt_bits_repr_usize(n: usize) -> usize {
    if n == 0 {
        1
    } else {
        n.ilog2() as usize + 1
    }
}

/// Returns the number of bits required to encode the given number.
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

/// Encodes [`BigUint`] in big-endian as a left-padded byte-string of length `len`.
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

/// Computes the leading ones of a ['BigUInt']
pub fn leading_ones(x: BigUint) -> u64 {
    let mut leading_ones = 0;
    for limb in x.iter_u64_digits().rev() {
        let ones = limb.leading_ones();
        leading_ones += ones;
        if ones < 64 {
            break;
        }
    }
    leading_ones as u64
}

/// Computes the inverse of `a_u` modulo `m_u` (if it exists).
///
/// The arguments are
/// - `a_u` - an integer
/// - `m_u` - the modulus
///
// Returns the inverse of `a_u` mod `m_u` iff `gcd(a_u,m_u) == 1`
pub fn mod_inverse(a_u: &BigUint, m_u: &BigUint) -> Option<BigUint> {
    if m_u.is_zero() {
        return None;
    }
    let m = BigInt::from_biguint(Sign::Plus, m_u.clone());
    let mut t = (BigInt::zero(), BigInt::one());
    let mut r = (m.clone(), BigInt::from_biguint(Sign::Plus, a_u.clone()));
    while !r.1.is_zero() {
        let q = &r.0 / &r.1;
        //https://docs.rs/num-integer/0.1.45/src/num_integer/lib.rs.html#353
        let f = |mut r: (BigInt, BigInt)| {
            mem::swap(&mut r.0, &mut r.1);
            r.1 -= &q * &r.0;
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

/// Holds a hash table of the Baby-step giant-step algorithm for computing discrete logarithms with respect to `base` and `modulus`.
pub struct DiscreteLog {
    /// The hash table
    table: HashMap<BigUint, u32>,
    /// The modulus defining Z_modulus
    modulus: BigUint,
    //  The base an integer in Z_modulus
    base: BigUint,
}

impl DiscreteLog {
    /// Constructs a new pre-computation table for a given base and modulus
    pub fn new(base: BigUint, modulus: BigUint) -> Self {
        let base = base % &modulus;
        let mut table = HashMap::new();
        let mut k = BigUint::from(1u8);
        for j in 0..(1 << 16) {
            table.insert(k.clone(), j);
            k = (k * &base) % &modulus;
        }
        DiscreteLog {
            table,
            modulus,
            base,
        }
    }

    /// Constructs a new pre-computation table for a given base and group
    pub fn from_group(base: &GroupElement, group: &Group) -> Self {
        Self::new(base.to_biguint(), group.modulus())
    }

    /// Tries to find the discrete logarithm of given `y` with respect to fixed base and modulus using the Baby-step giant-step algorithm.
    pub fn find(&self, y: &BigUint) -> Option<BigUint> {
        let mut gamma = y.clone();
        let m = (1 << 16) as u32;
        let alpha_to_minus_m = match mod_inverse(
            &self.base.modpow(&BigUint::from(m), &self.modulus),
            &self.modulus,
        ) {
            Some(x) => x,
            None => return None,
        };
        for i in 0..m {
            match self.table.get(&gamma) {
                Some(j) => {
                    return Some(BigUint::from(i * m + j));
                }
                None => {
                    gamma = (gamma * &alpha_to_minus_m) % &self.modulus;
                }
            }
        }
        None
    }

    /// Tries to find the discrete logarithm of given group element `y` with respect to fixed base using the Baby-step giant-step algorithm.
    pub fn ff_find(&self, y: &GroupElement, field: &ScalarField) -> Option<FieldElement> {
        let y = y.to_biguint();
        // The given integer must be small enough
        if y >= self.modulus {
            return None;
        }
        // The base should have an order < field.order
        if self.base.modpow(&field.order(), &self.modulus) != BigUint::one() {
            return None;
        }
        let maybe_x = self.find(&y);
        maybe_x.map(|x| FieldElement::from(x, field))
    }
}

/// Computes a single Lagrange coefficient mod q.
///
/// That is `w_i = \prod_{l != i} l/(l-i) % q` as in Equation `67` of EG `2.0.0`.
///
/// The arguments are
/// - `xs` - the list of nodes, field elements in Z_q
/// - `i` - the node (and index) of the coefficient
/// - `field` - the field Z_q
///
/// The output of this function may be nonsensical if the elements in `xs` are not unique.
fn get_single_coefficient_at_zero_unchecked(
    xs: &[FieldElement],
    i: &FieldElement,
    field: &ScalarField,
) -> FieldElement {
    xs.iter()
        .filter_map(|l| {
            let l_minus_i = l.sub(i, field);
            let inv_l_minus_i = l_minus_i.inv(field)?;
            Some(l.mul(&inv_l_minus_i, field))
        })
        .fold(ScalarField::one(), |acc, s| acc.mul(&s, field))
}

/// Computes a single Lagrange coefficient mod q.
///
/// That is `w_i = \prod_{l != i} l/(l-i) % q` as in Equation `67` of EG `2.0.0`.
///
/// The arguments are
/// - `xs` - the list of nodes, field elements in Z_q
/// - `i` - the node (and index) of the coefficient
/// - `field` - the field Z_q
///
/// The function returns `None` if `i` is not in `xs` or if the nodes in `xs` are not unique.
pub fn get_single_coefficient_at_zero(
    xs: &[FieldElement],
    i: &FieldElement,
    field: &ScalarField,
) -> Option<FieldElement> {
    if !xs.contains(i) || !xs.iter().all_unique() {
        return None;
    }
    Some(get_single_coefficient_at_zero_unchecked(xs, i, field))
}

/// Computes the Lagrange coefficients mod q
///
/// That is the list of  `w_i = \prod_{l != i} l/(l-i) % q` as in Equation `67` of EG `2.0.0`.
/// The arguments are
/// - `xs` - the list of nodes, field elements in Z_q
/// - `field` - the field Z_q
///
/// The output of this function may be nonsensical if the elements in `xs` are not unique.
fn get_lagrange_coefficients_at_zero_unchecked(
    xs: &[FieldElement],
    field: &ScalarField,
) -> Vec<FieldElement> {
    let mut coeffs = vec![];
    for i in xs {
        let w_i = get_single_coefficient_at_zero_unchecked(xs, i, field);
        coeffs.push(w_i);
    }
    coeffs
}

/// Computes the Lagrange interpolation in the field Z_q.
///
/// The arguments are
/// - `xs` - the list of nodes, field elements in Z_q
/// - `ys` - the list of values, field elements in Z_q
/// - `field` - the field Z_q
///
/// The function returns `None` if the nodes in `xs` are not unique or if `xs` and `ys` are not of the same length.
pub fn field_lagrange_at_zero(
    xs: &[FieldElement],
    ys: &[FieldElement],
    field: &ScalarField,
) -> Option<FieldElement> {
    if xs.len() != ys.len() || !xs.iter().all_unique() {
        return None;
    }
    let coeffs = get_lagrange_coefficients_at_zero_unchecked(xs, field);
    let y0 = zip(coeffs, ys)
        .map(|(c, y)| c.mul(y, field))
        .fold(ScalarField::zero(), |acc, s| acc.add(&s, field));
    Some(y0)
}

/// Computes the Lagrange interpolation in the exponent of group element.
///
/// The arguments are
/// - xs - the list of nodes, field elements in Z_q
/// - ys - the list of values (in the exponent), group elements in Z_p^r
/// - `field` - the field Z_q
/// - `group` - the group Z_p^r
///
/// The function returns `None` if the nodes in `xs` are not unique or if `xs` and `ys` are not of the same length.
pub fn group_lagrange_at_zero(
    xs: &[FieldElement],
    ys: &[GroupElement],
    field: &ScalarField,
    group: &Group,
) -> Option<GroupElement> {
    if xs.len() != ys.len() || !xs.iter().all_unique() {
        return None;
    }
    let coeffs = get_lagrange_coefficients_at_zero_unchecked(xs, field);
    let y0 = zip(coeffs, ys)
        .map(|(c, y)| y.exp(&c, group))
        .fold(Group::one(), |acc, s| acc.mul(&s, group));
    Some(y0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::csprng::Csprng;

    use super::*;
    use num_integer::Integer;
    use num_traits::Num;

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

    fn get_toy_algebras() -> (ScalarField, Group) {
        (
            ScalarField::new_unchecked(BigUint::from(127_u8)),
            Group::new_unchecked(
                BigUint::from(59183_u32),
                BigUint::from(466_u32),
                BigUint::from(32616_u32),
            ),
        )
    }

    fn get_medium_toy_algebras() -> (ScalarField, Group) {
        (
            ScalarField::new_unchecked(BigUint::from(4294967291_u32)),
            Group::new_unchecked(
                BigUint::from_str_radix("FFFFFFFF93C46B0FB6C381D8FFFFFFFF", 16).unwrap(),
                BigUint::from_str_radix("000000010000000493C46B269999999A", 16).unwrap(),
                BigUint::from_str_radix("29D995240DFB12B36FD0F8CCE06B657D", 16).unwrap(),
            ),
        )
    }

    #[test]
    fn test_group_dlog() {
        let mut csprng = Csprng::new(&[0u8]);
        let (field, group) = get_medium_toy_algebras();

        let h = group.random_group_elem(&mut csprng);
        let dl = DiscreteLog::from_group(&h, &group);

        for _ in 0..10 {
            let i = csprng.next_u32();
            let y = h.pow(i, &group);
            assert_eq!(
                dl.ff_find(&y, &field).unwrap(),
                FieldElement::from(i, &field)
            );
        }
    }

    #[test]
    fn test_lagrange_interpolation() {
        // Toy parameters according to specs
        let (field, group) = get_toy_algebras();

        // Test polynomial x^2-1
        let xs = [
            FieldElement::from(1_u8, &field),
            FieldElement::from(2_u8, &field),
            FieldElement::from(3_u8, &field),
        ];
        let ys = [
            FieldElement::from(0_u8, &field),
            FieldElement::from(3_u8, &field),
            FieldElement::from(8_u8, &field),
        ];
        let group_ys: Vec<_> = ys.iter().map(|x| group.g_exp(x)).collect();
        // -1 mod q
        let x_0 = FieldElement::from(126_u8, &field);
        let g_x_0 = group.g_exp(&x_0);

        assert_eq!(field_lagrange_at_zero(&xs, &ys, &field), Some(x_0));
        assert_eq!(
            group_lagrange_at_zero(&xs, &group_ys, &field, &group),
            Some(g_x_0)
        );

        // List of different length
        assert_eq!(field_lagrange_at_zero(&xs[0..2], &ys, &field), None);
        assert_eq!(field_lagrange_at_zero(&xs, &ys[0..2], &field), None);
        assert_eq!(
            group_lagrange_at_zero(&xs[0..2], &group_ys, &field, &group),
            None
        );
        assert_eq!(
            group_lagrange_at_zero(&xs, &group_ys[0..2], &field, &group),
            None
        );
        // Repeated nodes
        let xs = [
            FieldElement::from(1_u8, &field),
            FieldElement::from(2_u8, &field),
            FieldElement::from(2_u8, &field),
        ];
        assert_eq!(field_lagrange_at_zero(&xs, &ys, &field), None);
        assert_eq!(group_lagrange_at_zero(&xs, &group_ys, &field, &group), None);
    }

    #[test]
    fn test_single_lagrange_coefficient() {
        // Toy parameters according to specs
        let (field, _) = get_toy_algebras();
        // Test polynomial x^2 -1
        let xs = [
            FieldElement::from(1_u8, &field),
            FieldElement::from(2_u8, &field),
            FieldElement::from(3_u8, &field),
        ];
        let x = FieldElement::from(1_u8, &field);
        let exp_c = FieldElement::from(3_u8, &field);
        assert_eq!(
            get_single_coefficient_at_zero(&xs, &x, &field),
            Some(exp_c),
            "The coefficient at 1 should be 3."
        );

        let x = FieldElement::from(4_u8, &field);
        assert_eq!(
            get_single_coefficient_at_zero(&xs, &x, &field),
            None,
            "The function should not allow to compute coefficients for i outside of xs"
        );
        // Repeated nodes
        let xs = [
            FieldElement::from(1_u8, &field),
            FieldElement::from(2_u8, &field),
            FieldElement::from(2_u8, &field),
        ];
        let x = FieldElement::from(1_u8, &field);
        assert_eq!(
            get_single_coefficient_at_zero(&xs, &x, &field),
            None,
            "The function should reject xs with non-unique elements"
        );
    }
}
