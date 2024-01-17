#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides wrappers around `BigUnit` to separate group and field elements in the code.

use crate::{
    algebra_utils::{cnt_bits_repr, mod_inverse, to_be_bytes_left_pad},
    csprng::Csprng,
    prime::is_prime,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

/// A an element of field `Z_q`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FieldElement(
    #[serde(
        serialize_with = "crate::biguint_serde::biguint_serialize",
        deserialize_with = "crate::biguint_serde::biguint_deserialize"
    )]
    BigUint,
);

/// The finite field `Z_q` of integers modulo prime `q`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScalarField {
    /// Subgroup order.
    #[serde(
        serialize_with = "crate::biguint_serde::biguint_serialize",
        deserialize_with = "crate::biguint_serde::biguint_deserialize"
    )]
    q: BigUint,
}

impl FieldElement {
    /// Performs field addition.
    /// 
    /// That is the function computes `(self + other) % q` where `q` is the field order.
    pub fn add(&self, other: &FieldElement, field: &ScalarField) -> Self {
        FieldElement((&self.0 + &other.0) % &field.q)
    }

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
    pub fn pow<T>(&self, exponent: T, field: &ScalarField) -> FieldElement
    where
        BigUint: From<T>,
    {
        let x = BigUint::from(exponent);
        FieldElement(self.0.modpow(&x, &field.q))
    }

    /// Creates a field element from a given integer.
    pub fn from<T>(x: T, field: &ScalarField) -> Self
    where
        BigUint: From<T>,
    {
        let x = BigUint::from(x);
        FieldElement(x % &field.q)
    }

    /// Creates a field element from a bytes vector.
    ///
    /// Bytes interpreted as an big-endian encoded integer that is then reduced modulo order `q`.
    pub fn from_bytes_be(x: &[u8], field: &ScalarField) -> Self {
        let x_int = BigUint::from_bytes_be(x);
        FieldElement(x_int % &field.q)
    }

    /// Returns the left padded big-endian encoding of the field element.
    ///
    /// The encoding follows Section 5.1.2 in the specs. 
    pub fn to_be_bytes_left_pad(&self, field: &ScalarField) -> Vec<u8> {
        to_be_bytes_left_pad(&self.0, field.l_q())
    }

    /// Returns true if the element is zero.
    pub fn is_zero(&self) -> bool {
        BigUint::is_zero(&self.0)
    }

    /// Checks if the element is a valid member of the given field.
    ///
    /// This method return true iff `0 <= self < q` where `q` is the field order.
    pub fn is_valid(&self, field: &ScalarField) -> bool {
        // It is enough to check the upper bound as self.0 is unsigned.
        self.0 < field.q
    }
}

impl ScalarField {
    /// Constructs a new scalar field from a given order.
    ///
    /// This function returns `None` if the given order is not prime.
    pub fn new(order: BigUint, csprng: &mut Csprng) -> Option<Self> {
        let f = ScalarField { q: order };
        if f.is_valid(csprng) {
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

    /// The function validates the given field by checking that the modulus is prime.
    pub fn is_valid(&self, csprng: &mut Csprng) -> bool {
        is_prime(&self.q, csprng)
    }

    /// Returns one as a field element.
    pub fn one() -> FieldElement {
        FieldElement(BigUint::one())
    }

    /// Returns zero as a field element.
    pub fn zero() -> FieldElement {
        FieldElement(BigUint::zero())
    }

    /// Returns a random field element, i.e., a uniform random integer in `[0,q)` where `q` is the field order.
    ///
    /// The given `csprng` is assumed to be a secure randomness generator.
    pub fn random_field_elem(&self, csprng: &mut Csprng) -> FieldElement {
        FieldElement(csprng.next_biguint_lt(&self.q))
    }

    /// Returns the order `q` of the field
    pub fn order(&self) -> BigUint {
        self.q.clone()
    }

    /// Returns the length of the byte-array representation of field order `q`.
    /// 
    /// For the standard parameter field this is `32`.
    pub fn l_q(&self) -> usize {
        (cnt_bits_repr(&self.q) + 7) / 8
    }
}

/// An element of the multiplicative group `Z_p^r`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupElement(
    #[serde(
        serialize_with = "crate::biguint_serde::biguint_serialize",
        deserialize_with = "crate::biguint_serde::biguint_deserialize"
    )]
    BigUint,
);

/// The group `Z_p^r`, a multiplicative subgroup of `Z_p`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    /// Prime modulus `p`.
    #[serde(
        serialize_with = "crate::biguint_serde::biguint_serialize",
        deserialize_with = "crate::biguint_serde::biguint_deserialize"
    )]
    p: BigUint,
    /// Cofactor of `q` in `p − 1``.
    #[serde(
        serialize_with = "crate::biguint_serde::biguint_serialize",
        deserialize_with = "crate::biguint_serde::biguint_deserialize"
    )]
    r: BigUint,
    /// Subgroup generator `g`.
    #[serde(
        serialize_with = "crate::biguint_serde::biguint_serialize",
        deserialize_with = "crate::biguint_serde::biguint_deserialize"
    )]
    g: BigUint,
}

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
    pub fn pow<T>(&self, exponent: T, group: &Group) -> GroupElement
    where
        BigUint: From<T>,
    {
        let x = BigUint::from(exponent);
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
        let elem_has_order_q = self.pow(group.order(), group).0.is_one();
        elem_less_than_p && elem_has_order_q
    }

    /// Returns the left padded big-endian encoding of the group element.
    ///
    /// The encoding follows Section 5.1.1 in the specs.
    pub fn to_be_bytes_left_pad(&self, group: &Group) -> Vec<u8> {
        to_be_bytes_left_pad(&self.0, group.l_p())
    }

    pub fn to_biguint(&self) -> BigUint {
        self.0.clone()
    }
}

impl Group {
    /// Constructs a new multiplicative integer group `Z_p^r`.
    /// 
    /// The arguments are 
    /// - `modulus` - the modulus `p`
    /// - `cofactor`- the cofactor `r`
    /// - `generator` - a generator `g`
    ///
    /// This function checks that the group is valid according to [`Group::is_valid`].
    pub fn new(
        modulus: BigUint,
        cofactor: BigUint,
        generator: BigUint,
        csprng: &mut Csprng,
    ) -> Option<Self> {
        let group = Group {
            p: modulus,
            r: cofactor,
            g: generator,
        };
        if group.is_valid(csprng) {
            return Some(group);
        }
        None
    }

    /// Constructs a new group without checking the validity according to [`Group::is_valid`].
    pub fn new_unchecked(modulus: BigUint, cofactor: BigUint, generator: BigUint) -> Self {
        Group {
            p: modulus,
            r: cofactor,
            g: generator,
        }
    }

    /// This function checks that the given group is valid.
    ///
    /// A group is considered valid if:
    /// - the `modulus` is prime,
    /// - the `order` is prime, `< modulus-1`, and does not divide the `co-factor`,
    /// - the `generator` has order `order`,
    /// - the `co-factor` is non-zero,
    pub fn is_valid(&self, csprng: &mut Csprng) -> bool {
        // modulus must be prime
        if !is_prime(&self.p, csprng) {
            return false;
        }
        // the co-factor must be non-zero
        if self.r.is_zero() {
            return false;
        }
        let order = (&self.p - BigUint::one()) / &self.r;
        // the order must be prime, < modulus-1, and must not divide the co-factor
        if !is_prime(&order, csprng) || self.r.is_one() || (&self.r % &order).is_zero() {
            return false;
        }
        // This ensures that the order of generator is at most `order`
        if !self.g.modpow(&order, &self.p).is_one() {
            return false;
        }
        // If generator is not one (and `order` is prime) => order of generator is `order`
        if self.g.is_one() {
            return false;
        }
        true
    }

    /// Returns a uniform random group element
    /// 
    /// The element is generated by selecting a random integer in `[0,q)` 
    /// and computing `g^q % p` where `q` is the group order, `g` a generator, and `p` the modulus.
    /// 
    /// The given `csprng` is assumed to be a secure randomness generator.
    pub fn random_group_elem(&self, csprng: &mut Csprng) -> GroupElement {
        let q = self.order();
        let field_elem = FieldElement(csprng.next_biguint_lt(&q));
        self.g_exp(&field_elem)
    }

    /// Returns generator `g` raised to the power of `x` mod modulus `p`.
    pub fn g_exp(&self, x: &FieldElement) -> GroupElement {
        GroupElement(self.g.modpow(&x.0, &self.p))
    }

    /// Returns one as a group element.
    pub fn one() -> GroupElement {
        GroupElement(BigUint::one())
    }

    /// Returns the order of the group
    pub fn order(&self) -> BigUint {
        (&self.p - BigUint::one()) / &self.r
    }

    /// Returns the modulus of the group
    pub fn modulus(&self) -> BigUint {
        self.p.clone()
    }

    /// Returns a generator of the group
    pub fn generator(&self) -> GroupElement {
        GroupElement(self.g.clone())
    }

    /// Returns the length of the byte array representation of modulus `p`.
    /// 
    /// For the standard parameter group this is `512`.
    pub fn l_p(&self) -> usize {
        (cnt_bits_repr(&self.p) + 7) / 8
    }
}

/// This function checks if the given group and field have the same order.
pub fn group_matches_field(group: &Group, field: &ScalarField) -> bool {
    group.order() == field.q
}

// Unit tests for algebra.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::group_matches_field;
    use crate::algebra::{FieldElement, Group, GroupElement, ScalarField};
    use crate::csprng::Csprng;
    use num_bigint::BigUint;

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

    #[test]
    fn test_field_operations() {
        // Toy parameters according to specs
        let (field, _) = get_toy_algebras();

        let a = FieldElement::from(115_u8, &field);
        let b = FieldElement::from(37_u8, &field);

        // 242 =  115 mod 127
        assert_eq!(a, FieldElement::from(242_u8, &field));

        // 25 = (115 + 37) mod 127
        assert_eq!(a.add(&b, &field), FieldElement::from(25_u8, &field));

        // 78 = (115 - 37) mod 127
        assert_eq!(a.sub(&b, &field), FieldElement::from(78_u8, &field));

        // -78 = 49 mod 127
        assert_eq!(b.sub(&a, &field), FieldElement::from(49_u8, &field));

        assert_eq!(b.sub(&b, &field), ScalarField::zero());

        // 4255 = 64 mod 127
        assert_eq!(a.mul(&b, &field), FieldElement::from(64_u8, &field));

        // 115 * 74 = 1 mod 127
        let a_inv = a.inv(&field).unwrap();
        assert_eq!(a_inv, FieldElement::from(74_u8, &field));
        assert_eq!(a.mul(&a_inv, &field), ScalarField::one());
    }

    #[test]
    fn test_group_operations() {
        let mut csprng = Csprng::new(b"testing group operations");
        // Toy parameters according to specs
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
            let u = group.random_group_elem(&mut csprng);
            assert!(u.is_valid(&group));
        }

        // Testing soundness
        assert!(!h.is_valid(&group));
    }

    #[test]
    fn test_field_group_validity() {
        let mut csprng = Csprng::new(b"testing field/group validity");
        let (field, group) = get_toy_algebras();
        let invalid_field = ScalarField::new_unchecked(BigUint::from(125_u8));
        let invalid_modulus_group = Group::new_unchecked(
            BigUint::from(59185_u32),
            BigUint::from(466_u32),
            BigUint::from(32616_u32),
        );
        let invalid_generator_group = Group::new_unchecked(
            BigUint::from(59183_u32),
            BigUint::from(466_u32),
            BigUint::from(1_u32),
        );

        // order = 68890/830 = 83 is prime, but does not divide the cofactor!
        let invalid_cofactor_group = Group::new_unchecked(
            BigUint::from(68891_u32),
            BigUint::from(830_u32),
            BigUint::from(59398_u32),
        );

        // Testing correctness
        assert!(
            field.is_valid(&mut csprng),
            "Prime order fields should validate!"
        );
        assert!(
            group.is_valid(&mut csprng),
            "Prime order groups with proper parameters should validate!"
        );
        assert!(group_matches_field(&group, &field));

        // Testing soundness
        assert!(
            !invalid_field.is_valid(&mut csprng),
            "Non-prime order fields should fail!"
        );
        assert!(!group_matches_field(&group, &invalid_field));
        assert!(
            !invalid_modulus_group.is_valid(&mut csprng),
            "Groups with a non-prime modulus should fail!"
        );
        assert!(
            !invalid_generator_group.is_valid(&mut csprng),
            "Groups with an invalid generator should fail!"
        );
        assert!(
            !invalid_cofactor_group.is_valid(&mut csprng),
            "Groups with an invalid cofactor should fail!"
        );
    }
}
