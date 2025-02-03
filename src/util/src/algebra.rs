#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides wrappers around `BigUnit` to separate group and field elements in the code.

use std::ops::Deref;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    algebra_utils::{cnt_bits_repr, mod_inverse, to_be_bytes_left_pad},
    base16::to_string_uppercase_hex_infer_len,
    csrng::Csrng,
    prime::is_prime,
};

/// Sub-optimal method of zeroing-out [`BigUint`] type on a best-effort basis.
/// Unfortunately, BigUint does not expose enough of its internals to provide
/// any guarantees.
fn try_to_zeroize_biguint(b: &mut BigUint) {
    //? TODO perhaps move this function somewhere commmon?

    // Setting bits in LSB to MSB order should avoid reallocation until we've overwritten
    // the internal data. Setting them to `1` looks like it might be a little faster.
    for ix in 0..b.bits().next_multiple_of(32) {
        b.set_bit(ix, true)
    }

    b.set_zero();
}

/// A an element of field `Z_q` as defined by [`ScalarField`].
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FieldElement(
    #[serde(
        //? TODO don't hardcode 256 bits
        serialize_with = "crate::biguint_serde::biguint_serialize_256_bits",
        deserialize_with = "crate::biguint_serde::biguint_deserialize_256_bits"
    )]
    BigUint,
);

impl FieldElement {
    /// The field element with the value `0`.
    pub fn zero() -> Self {
        FieldElement(BigUint::zero())
    }

    /// The numeric value of the field element. Guaranteed to be `< q`.
    pub fn value(&self) -> &BigUint {
        &self.0
    }

    /// Performs field addition.
    ///
    /// That is the function computes `(self + other) % q` where `q` is the field order.
    pub fn add(&self, other: &FieldElement, field: &ScalarField) -> Self {
        FieldElement((&self.0 + &other.0) % &field.q)
    }

    /*
    /// Performs field assignment addition.
    ///
    /// `self = (self + other) % q` where `q` is the field order.
    fn add_assign(&mut self, rhs: Self, field: &ScalarField) {
        self.0 += rhs.0;
        self.0 &= &field.q;
    }
    */

    /// Performs field subtraction.
    ///
    /// That is the function computes `(self - other) % q` where `q` is the field order.
    pub fn sub(&self, other: &FieldElement, field: &ScalarField) -> Self {
        if self.0 >= other.0 {
            FieldElement((&self.0 - &other.0) % &field.q)
        } else {
            FieldElement((&field.q - (&other.0 - &self.0)) % &field.q)
        }
    }

    /// Performs field multiplication.
    ///
    /// That is the function computes `(self * other) % q` where `q` is the field order.
    pub fn mul(&self, other: &FieldElement, field: &ScalarField) -> Self {
        FieldElement((&self.0 * &other.0) % &field.q)
    }

    /// Computes the multiplicative inverse of a field element if it exists
    /// The arguments are
    /// - self - a field element
    /// - field - the scalar field
    ///
    // Returns the inverse in `Z_q` if it exist, i.e., iff `gcd(self,q) == 1`
    pub fn inv(&self, field: &ScalarField) -> Option<Self> {
        mod_inverse(&self.0, &field.q).map(FieldElement)
    }

    /// Performs modular exponentiation of the field element with a given integer exponent.
    pub fn pow(&self, exponent: impl Into<BigUint>, field: &ScalarField) -> FieldElement {
        let x = exponent.into();
        FieldElement(self.0.modpow(&x, &field.q))
    }

    /// Creates a field element from a given integer.
    pub fn from<T>(x: T, field: &ScalarField) -> Self
    where
        T: Into<BigUint>,
    {
        let x: BigUint = x.into();
        FieldElement(x % &field.q)
    }

    /// Creates a field element from a bytes vector.
    ///
    /// Bytes interpreted as an big-endian encoded integer that is then reduced modulo order `q`.
    pub fn from_bytes_be(x: &[u8], field: &ScalarField) -> Self {
        let x_int = BigUint::from_bytes_be(x);
        FieldElement(x_int % &field.q)
    }

    /// Returns the big-endian encoding of the field element left-padded to 32 bytes.
    ///
    /// This function will panic the field element encoding requires more than 32 bytes.
    /// All fields defined in the specification require <= 32 bytes to encode an element.
    pub fn to_32_be_bytes(&self) -> Vec<u8> {
        to_be_bytes_left_pad(&self.0, 32)
    }

    /// Returns the big-endian encoding of the field element left-padded to 32 bytes.
    /// Returns `None` if the field element doesn't fit for some reason.
    pub fn try_into_32_be_bytes_arr(&self) -> Option<[u8; 32]> {
        let mut by_arr = [0u8; 32];
        let mut it_src_u64 = self.0.iter_u64_digits();
        for dst_chunk in by_arr.rchunks_exact_mut(8) {
            let u = it_src_u64.next()?;
            dst_chunk.clone_from_slice(&u.to_be_bytes());
        }
        for u in it_src_u64 {
            if u != 0 {
                return None;
            }
        }
        Some(by_arr)
    }

    /// Returns the left padded big-endian encoding of the field element.
    ///
    /// The encoding follows Section 5.1.2 in the specs.
    pub fn to_be_bytes_left_pad(&self, field: &ScalarField) -> Vec<u8> {
        to_be_bytes_left_pad(&self.0, field.q_len_bytes())
    }

    /// Returns true if the element is zero.
    pub fn is_zero(&self) -> bool {
        BigUint::is_zero(&self.0)
    }

    /// Checks if the element is a valid member of the given field.
    ///
    /// This method returns true iff `0 <= self < q` where `q` is the field order.
    pub fn is_valid(&self, field: &ScalarField) -> bool {
        // It is enough to check the upper bound as self.0 is unsigned.
        self.0 < field.q
    }
}

impl std::ops::Deref for FieldElement {
    type Target = BigUint;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let alternate = f.alternate();
        let mut dt = f.debug_tuple("FieldElement");
        if alternate {
            dt.field(&to_string_uppercase_hex_infer_len(&self.0));
            dt.finish()
        } else {
            dt.finish_non_exhaustive()
        }
    }
}

impl std::fmt::Display for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Debug>::fmt(self, f)
    }
}

impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        try_to_zeroize_biguint(&mut self.0)
    }
}

impl Drop for FieldElement {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for FieldElement {}

#[derive(thiserror::Error, Clone, Debug)]
pub enum FieldError {
    #[error("Could not convert field element to `{0}`: {1}")]
    FieldElementConvertTo(&'static str, String),
}

impl TryFrom<&FieldElement> for u64 {
    type Error = FieldError;
    #[inline]
    fn try_from(fe: &FieldElement) -> Result<u64, Self::Error> {
        u64::try_from(fe.deref())
            .map_err(|e| FieldError::FieldElementConvertTo("u64", e.to_string()))
    }
}

impl TryFrom<FieldElement> for u64 {
    type Error = FieldError;
    #[inline]
    fn try_from(fe: FieldElement) -> Result<u64, Self::Error> {
        TryFrom::<&FieldElement>::try_from(&fe)
    }
}

/// The finite field `Z_q` of integers modulo prime `q`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScalarField {
    /// Subgroup order.
    #[serde(
        //? TODO don't hardcode 256 bits
        serialize_with = "crate::biguint_serde::biguint_serialize_256_bits",
        deserialize_with = "crate::biguint_serde::biguint_deserialize_256_bits"
    )]
    q: BigUint,
}

impl ScalarField {
    /// Constructs a new scalar field from a given order.
    ///
    /// This function returns `None` if the given order is not prime.
    /// Checking the validity of inputs is expensive.
    /// A field should therefore be constructed once and then reused as much as possible.
    ///
    /// Alternatively, one can use fixed, *trusted/tested* parameters with [`ScalarField::new_unchecked`].
    pub fn new(order: BigUint, csrng: &dyn Csrng) -> Option<Self> {
        let f = ScalarField { q: order };
        if f.is_valid(csrng) {
            return Some(f);
        }
        None
    }

    /// Constructs a new scalar field from a given order without checking primality.
    ///
    /// This function *assumes* that the given order is prime.
    pub fn new_unchecked(order: BigUint) -> Self {
        ScalarField { q: order }
    }

    /// The function validates the given field by checking that the modulus is prime. The call is expensive.
    pub fn is_valid(&self, csrng: &dyn Csrng) -> bool {
        is_prime(&self.q, csrng)
    }

    /// Returns one, the neutral element of multiplication, as a field element.
    pub fn one() -> FieldElement {
        FieldElement(BigUint::one())
    }

    /// Returns zero, the neutral element of addition, as a field element.
    pub fn zero() -> FieldElement {
        FieldElement(BigUint::zero())
    }

    /// Returns a random field element, i.e., a uniform random integer in `[0,q)` where `q` is the
    /// field order.
    pub fn random_field_elem(&self, csrng: &dyn Csrng) -> FieldElement {
        // Unwrap() is justified here because the field order was checked for validity.
        #[allow(clippy::unwrap_used)]
        FieldElement(csrng.next_biguint_lt(&self.q).unwrap())
    }

    /// Returns the order `q` of the field
    pub fn order(&self) -> &BigUint {
        &self.q
    }

    /// Returns the length of the byte-array representation of field order `q`.
    ///
    /// For the standard parameter field this is `32`.
    pub fn q_len_bytes(&self) -> usize {
        (cnt_bits_repr(&self.q) + 7) / 8
    }
}

impl std::fmt::Debug for ScalarField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let alternate = f.alternate();
        let mut ds = f.debug_struct("ScalarField");
        if alternate {
            ds.field("q", &to_string_uppercase_hex_infer_len(&self.q));
            ds.finish()
        } else {
            ds.finish_non_exhaustive()
        }
    }
}

impl std::fmt::Display for ScalarField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Debug>::fmt(self, f)
    }
}

/// An element of the multiplicative group `Z_p^r` as defined by [`Group`].
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupElement(
    #[serde(
        //? TODO don't hardcode 4096 bits
        serialize_with = "crate::biguint_serde::biguint_serialize_4096_bits",
        deserialize_with = "crate::biguint_serde::biguint_deserialize_4096_bits"
    )]
    BigUint,
);

impl GroupElement {
    /// Multiplies the group element with another group element.
    ///
    /// That is the function computes `(self * other) mod p` where `p` is the group modulus.
    pub fn mul(&self, other: &GroupElement, group: &Group) -> GroupElement {
        GroupElement((&self.0 * &other.0) % &group.p)
    }

    /// Computes the (multiplicative) inverse of a group element.
    ///
    /// For valid group elements this function will always return some value.
    pub fn inv(&self, group: &Group) -> Option<Self> {
        mod_inverse(&self.0, &group.p).map(GroupElement)
    }

    /// Performs modular exponentiation of the group element with a given integer exponent.
    pub fn pow(&self, exponent: impl Into<BigUint>, group: &Group) -> GroupElement {
        let x = exponent.into();
        GroupElement(self.0.modpow(&x, &group.p))
    }

    /// Performs modular exponentiation of the group element with a given field element.
    ///
    /// This defines an action of the field over the group.
    pub fn exp(&self, exponent: &FieldElement, group: &Group) -> GroupElement {
        GroupElement(self.0.modpow(&exponent.0, &group.p))
    }

    /// Checks if the element is a valid member of the given group.
    ///
    /// This method return true iff `0 <= self < p` and `self^q % p == 1` where `p` is the group modulus and `q` the group order.
    pub fn is_valid(&self, group: &Group) -> bool {
        // It is enough to check the upper bound as self.0 is unsigned.
        let elem_less_than_p = self.0 < group.p;
        let elem_has_order_q = self.0.modpow(&group.q, &group.p).is_one();
        elem_less_than_p && elem_has_order_q
    }

    /// Returns the left padded big-endian encoding of the group element.
    ///
    /// The encoding follows Section 5.1.1 in the specs.
    pub fn to_be_bytes_left_pad(&self, group: &Group) -> Vec<u8> {
        to_be_bytes_left_pad(&self.0, group.p_len_bytes())
    }

    /// Returns a reference to group element as BigUint
    pub fn as_biguint(&self) -> &BigUint {
        &self.0
    }
}

impl std::fmt::Debug for GroupElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let alternate = f.alternate();
        let mut dt = f.debug_tuple("GroupElement");
        if alternate {
            dt.field(&to_string_uppercase_hex_infer_len(&self.0));
            dt.finish()
        } else {
            dt.finish_non_exhaustive()
        }
    }
}

impl std::fmt::Display for GroupElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Debug>::fmt(self, f)
    }
}

impl Zeroize for GroupElement {
    fn zeroize(&mut self) {
        try_to_zeroize_biguint(&mut self.0)
    }
}

impl Drop for GroupElement {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for GroupElement {}

/// The group `Z_p^r`, a multiplicative subgroup of `Z_p`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    /// Prime modulus `p`.
    #[serde(
        //? TODO don't hardcode 4096 bits
        serialize_with = "crate::biguint_serde::biguint_serialize_4096_bits",
        deserialize_with = "crate::biguint_serde::biguint_deserialize_4096_bits"
    )]
    p: BigUint,

    /// Subgroup generator `g`.
    #[serde(
        //? TODO don't hardcode 4096 bits
        serialize_with = "crate::biguint_serde::biguint_serialize_4096_bits",
        deserialize_with = "crate::biguint_serde::biguint_deserialize_4096_bits"
    )]
    g: BigUint,

    /// Group order `q`.
    #[serde(
        //? TODO don't hardcode 256 bits
        serialize_with = "crate::biguint_serde::biguint_serialize_256_bits",
        deserialize_with = "crate::biguint_serde::biguint_deserialize_256_bits"
    )]
    q: BigUint,
}

impl Group {
    /// Constructs a new multiplicative integer group `Z_p^r`.
    ///
    /// The arguments are
    /// - `modulus` - the modulus `p`
    /// - `order`- the order `q`
    /// - `generator` - a generator `g`
    ///
    /// This function checks that the group is valid according to [`Group::is_valid`].
    /// Checking the validity of inputs is expensive.
    /// A group should therefore be constructed once and then reused as much as possible.
    ///
    /// Alternatively, one can use fixed, *trusted/tested* parameters with [`Group::new_unchecked`].
    pub fn new(
        modulus: BigUint,
        order: BigUint,
        generator: BigUint,
        csrng: &dyn Csrng,
    ) -> Option<Self> {
        let group = Group {
            p: modulus,
            g: generator,
            q: order,
        };
        if group.is_valid(csrng) {
            return Some(group);
        }
        None
    }

    /// Constructs a new group without checking the validity according to [`Group::is_valid`].
    pub fn new_unchecked(modulus: BigUint, order: BigUint, generator: BigUint) -> Self {
        Group {
            p: modulus,
            g: generator,
            q: order,
        }
    }

    /// This function checks that the given group is valid. The call is expensive.
    ///
    /// A group is considered valid if:
    /// - the `modulus` is prime,
    /// - the `order` is prime, divides `modulus-1`, but not `(modulus-1)/order`,
    /// - the `generator` has order `order`,
    /// - and `(modulus-1)/ 2order` is prime
    pub fn is_valid(&self, csrng: &dyn Csrng) -> bool {
        // Expensive primality testing is done last

        // The order `q` must divide `p-1` but not `(p-1)/q` for modulus `p`.
        let p_minus_1 = &self.p - BigUint::one();
        let cofactor = &p_minus_1 / &self.q;
        if !(p_minus_1 % &self.q).is_zero() || (&cofactor % &self.q).is_zero() {
            return false;
        }

        // This ensures that the order of generator `g` is at most `q` and `g != 1`
        // and if `q` is prime => order of generator is `q`
        if self.g.is_one() || !self.g.modpow(&self.q, &self.p).is_one() {
            return false;
        }

        // The cofactor should be even otherwise (p-1)/2q is not prime
        // (this rules out cases like p=7 and q=2)
        if cofactor.is_odd() {
            return false;
        }
        let r_2 = cofactor / BigUint::from(2_u8);
        // All primality testing
        is_prime(&self.q, csrng) || is_prime(&self.p, csrng) || is_prime(&r_2, csrng)
    }

    /// Returns a uniform random group element
    ///
    /// The element is generated by selecting a random integer `x` in `[0,q)`
    /// and computing `g^x % p` where `q` is the group order, `g` a generator, and `p` the modulus.
    ///
    /// The given `csrng` is assumed to be a secure randomness generator.
    pub fn random_group_elem(&self, csrng: &dyn Csrng) -> GroupElement {
        // Unwrap() is justified here because the field order was checked for validity.
        #[allow(clippy::unwrap_used)]
        let field_elem = FieldElement(csrng.next_biguint_lt(&self.q).unwrap());
        self.g_exp(&field_elem)
    }

    /// Returns generator `g` raised to the power of `x` mod modulus `p`.
    pub fn g_exp(&self, x: &FieldElement) -> GroupElement {
        GroupElement(self.g.modpow(&x.0, &self.p))
    }

    /// Returns one, the neutral element, as a group element.
    pub fn one() -> GroupElement {
        GroupElement(BigUint::one())
    }

    /// Returns a reference to the order of the group
    pub fn order(&self) -> &BigUint {
        &self.q
    }

    /// Returns a reference to the modulus of the group
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// Returns a generator of the group
    pub fn generator(&self) -> GroupElement {
        GroupElement(self.g.clone())
    }

    /// Returns the length of the byte array representation of modulus `p`.
    ///
    /// For the standard parameter group this is `512`.
    pub fn p_len_bytes(&self) -> usize {
        (cnt_bits_repr(&self.p) + 7) / 8
    }

    /// Returns the length of the byte-array representation of field order `q`.
    ///
    /// For the standard parameter field this is `32`.
    pub fn q_len_bytes(&self) -> usize {
        (cnt_bits_repr(&self.q) + 7) / 8
    }

    /// This function checks if the group and the given field have the same order.
    pub fn matches_field(self: &Group, field: &ScalarField) -> bool {
        self.q == field.q
    }
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let alternate = f.alternate();
        let mut ds = f.debug_struct("Group");
        if alternate {
            ds.field("p", &to_string_uppercase_hex_infer_len(&self.p));
            ds.field("g", &to_string_uppercase_hex_infer_len(&self.g));
            ds.field("q", &to_string_uppercase_hex_infer_len(&self.q));
            ds.finish()
        } else {
            ds.finish_non_exhaustive()
        }
    }
}

impl std::fmt::Display for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Debug>::fmt(self, f)
    }
}

// Unit tests for algebra.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use num_bigint::BigUint;

    use crate::{
        algebra::{FieldElement, Group, GroupElement, ScalarField},
        csrng::{Csrng, DeterministicCsrng},
    };

    fn get_toy_algebras() -> (ScalarField, Group) {
        (
            ScalarField::new_unchecked(BigUint::from(127_u8)),
            Group::new_unchecked(
                BigUint::from(59183_u32),
                BigUint::from(127_u8),
                BigUint::from(32616_u32),
            ),
        )
    }

    #[test]
    fn test_field_operations() {
        // Toy election parameters according to specs
        let (field, _) = get_toy_algebras();

        let a = FieldElement::from(115_u8, &field);
        let b = FieldElement::from(37_u8, &field);

        // 242 =  115 mod 127
        assert_eq!(a, FieldElement::from(242_u8, &field));

        // 25 = (115 + 37) mod 127
        assert_eq!(a.add(&b, &field), FieldElement::from(25_u8, &field));

        // 78 = (115 - 37) mod 127
        assert_eq!(a.sub(&b, &field), FieldElement::from(78_u8, &field));

        // (37 - 115) = -78 = 49 mod 127
        assert_eq!(b.sub(&a, &field), FieldElement::from(49_u8, &field));

        assert_eq!(b.sub(&b, &field), ScalarField::zero());

        // 4255 = 64 mod 127
        assert_eq!(a.mul(&b, &field), FieldElement::from(64_u8, &field));

        // 115 ^ 23 = 69 mod 127
        assert_eq!(a.pow(23_u8, &field), FieldElement::from(69_u8, &field));

        // 115 * 74 = 1 mod 127
        let a_inv = a.inv(&field).unwrap();
        assert_eq!(a_inv, FieldElement::from(74_u8, &field));
        assert_eq!(a.mul(&a_inv, &field), ScalarField::one());
    }

    #[test]
    fn test_group_operations() {
        let csrng: &dyn Csrng = &DeterministicCsrng::from_seed_str("testing group operations");

        // Toy election parameters according to specs
        let (field, group) = get_toy_algebras();

        let a = FieldElement::from(115_u8, &field);
        let g1 = group.g_exp(&a);

        // g2 = group.g^{14} computed from sage
        let g2 = GroupElement(BigUint::from(38489_u32));

        // g3 = g1*g2 computed from sage
        let g3 = GroupElement(BigUint::from(48214_u32));

        // h is not a group element
        let h = GroupElement(BigUint::from(12345_u32));

        // Multiplicative inverse of g1 computed from sage
        let g1_inv = GroupElement(BigUint::from(58095_u32));

        // Testing correctness
        assert!(g1.is_valid(&group));
        assert!(g2.is_valid(&group));

        assert_eq!(g1.mul(&g2, &group), g3);

        assert_eq!(g1.inv(&group), Some(g1_inv.clone()));
        assert_eq!(g1.mul(&g1_inv, &group), Group::one());

        let g = group.generator();
        assert_eq!(g.pow(14_u32, &group), g2);

        for _ in 0..100 {
            let u = group.random_group_elem(csrng);
            assert!(u.is_valid(&group));
        }

        // Testing soundness
        assert!(!h.is_valid(&group));
    }

    #[test]
    fn test_field_group_validity() {
        let csrng: &dyn Csrng = &DeterministicCsrng::from_seed_str("testing field/group validity");

        let (field, group) = get_toy_algebras();
        let invalid_field = ScalarField::new_unchecked(BigUint::from(125_u8));
        let invalid_modulus_group = Group::new_unchecked(
            BigUint::from(59185_u32),
            BigUint::from(127_u8),
            BigUint::from(32616_u32),
        );
        let invalid_generator_group = Group::new_unchecked(
            BigUint::from(59183_u32),
            BigUint::from(127_u8),
            BigUint::from(1_u32),
        );
        // order = 68890/830 = 83 is prime, but does not divide the cofactor!
        let invalid_cofactor_group = Group::new_unchecked(
            BigUint::from(68891_u32),
            BigUint::from(83_u32),
            BigUint::from(59398_u32),
        );

        // Testing correctness
        assert!(field.is_valid(csrng), "Prime order fields should validate!");
        assert!(
            group.is_valid(csrng),
            "Prime order groups with proper parameters should validate!"
        );
        assert!(group.matches_field(&field));

        // Testing soundness
        assert!(
            !invalid_field.is_valid(csrng),
            "Non-prime order fields should fail!"
        );
        assert!(!group.matches_field(&invalid_field));
        assert!(
            !invalid_modulus_group.is_valid(csrng),
            "Groups with a non-prime modulus should fail!"
        );
        assert!(
            !invalid_generator_group.is_valid(csrng),
            "Groups with an invalid generator should fail!"
        );
        assert!(
            !invalid_cofactor_group.is_valid(csrng),
            "Groups with an invalid cofactor should fail!"
        );

        // The co-factor does not divide p-1
        let invalid_group = Group::new(
            BigUint::from(19_u8),
            BigUint::from(3_u8),
            BigUint::from(7_u8),
            csrng,
        );
        assert_eq!(invalid_group, None);
    }

    #[test]
    fn test_field_conversions() {
        let (field, _) = get_toy_algebras();

        // 65 is the field element from the bytes "A"
        let u = FieldElement(BigUint::from(65_u8));
        let u_from = FieldElement::from(65_u8, &field);
        let u_from_bytes = FieldElement::from_bytes_be(b"A", &field);
        assert_eq!(u, u_from);
        assert_eq!(u, u_from_bytes);

        // 69 = 16706 mod 127 is the field element from the bytes "AB".
        let v = FieldElement(BigUint::from(69_u16));
        let v_from = FieldElement::from(16706_u16, &field);
        let v_from_bytes = FieldElement::from_bytes_be(b"AB", &field);
        assert_eq!(v, v_from);
        assert_eq!(v, v_from_bytes);

        // Testing encoding of field elements as bytes.
        assert_eq!(u.to_be_bytes_left_pad(&field), vec![65_u8]);
        assert_eq!(v.to_be_bytes_left_pad(&field), vec![69_u8]);

        // Testing length of encoding
        assert_eq!(u.to_32_be_bytes().len(), 32)
    }
}
