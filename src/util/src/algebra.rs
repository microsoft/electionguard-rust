#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides wrappers around `BigUnit` to separate group and field elements in the code.

use crate::{csprng::Csprng, prime::is_prime, integer_util::{cnt_bits_repr, to_be_bytes_left_pad}};
use num_bigint::BigUint;
use serde::{Serialize, Deserialize};

/// A field element, i.e. an element of `Z_q`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldElement(BigUint);

/// The finite field `Z_q` of integers modulo q.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScalarField {
    /// Subgroup order.
    pub q: BigUint,
}

impl FieldElement {

    pub fn from_biguint(x: BigUint, field: &ScalarField) -> Self {
        FieldElement(x % &field.q)
    }

    /// Performs field addition modulo prime q.
    pub fn add(&self, other: &FieldElement, field: &ScalarField) -> Self {
        FieldElement((&self.0 + &other.0) % &field.q)
    }

    /// Performs field subtraction modulo prime q.
    pub fn sub(&self, other: &FieldElement, field: &ScalarField) -> Self {
        if self.0 > other.0 {
            FieldElement((&self.0 - &other.0) % &field.q)
        } else {
            FieldElement(&field.q - ((&other.0 - &self.0) % &field.q))
        }
    }

    /// Performs field multiplication modulo prime q.
    pub fn mul(&self, other: &FieldElement, field: &ScalarField) -> Self {
        FieldElement((&self.0 * &other.0) % &field.q)
    }

    /// Computes the multiplicative inverse of a field element if it exists
    pub fn inv(&self, field: &ScalarField) -> Option<Self> {
        todo!()
    }

    /// Returns the left padded big-endian encoding of the field element.
    /// 
    /// The encoding follows Section 5.1.2 in the specs. 
    pub fn to_be_bytes_left_pad(&self, field: &ScalarField) -> Vec<u8>{
        to_be_bytes_left_pad(&self.0, field.l_q())
    }
}

impl ScalarField {
    /// Constructs a new scalar field from a given order.
    ///
    /// This function returns `None` if the given order is not prime.
    pub fn new(order: BigUint, csprng: &mut Csprng) -> Option<ScalarField> {
        if is_prime(&order, csprng) {
            Some(ScalarField { q: order })
        } else {
            None
        }
    }

    /// Constructs a new scalar field from a given order.
    ///
    /// This function *assumes* that the given order is prime.
    /// The behavior may be undefined if the order is not prime.
    pub fn new_unchecked(order: BigUint) -> Self {
        ScalarField { q: order }
    }

    /// Returns a random field element, i.e. a uniform random integer in [0,q).
    ///
    /// The given `csprng` is assumed to be a secure randomness generator.
    pub fn random_field_elem(&self, csprng: &mut Csprng) -> FieldElement {
        FieldElement(csprng.next_biguint_lt(&self.q))
    }

    /// Returns the order of the field
    pub fn order(&self) -> BigUint {
        todo!()
    }

    /// Returns the length of the byte array representation of `q`
    pub fn l_q(&self) -> usize {
        (cnt_bits_repr(&self.q) + 7) / 8
    }
}

/// A group element, i.e. an element of `Z_p^r`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupElement(BigUint);

/// The group `Z_p^r`, a multiplicative subgroup of `Z_p`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    /// Prime modulus.
    pub p: BigUint,
    /// Cofactor of q in p − 1.
    pub r: BigUint,
    /// Subgroup generator.
    pub g: BigUint,
}

impl GroupElement {
    /// Performs group operation modulo prime p.
    pub fn mul(&self, other: &GroupElement, group: &Group) -> GroupElement {
        GroupElement((&self.0 * &other.0) % &group.p)
    }

    /// Computes the inverse of a group element.
    pub fn inv(&self, other: &GroupElement, group: &Group) -> Option<GroupElement> {
        todo!()
    }

    /// Computes the `exponent`-power of the given group element.
    pub fn exp(&self, exponent: &ScalarField, group: &Group) -> GroupElement {
        todo!()
    }

    /// Checks if the element is a valid member of the given group.
    ///
    /// This method return true iff 0 <= self < group.p and self^group.order() % p == 1
    pub fn is_valid(&self, group: &Group) -> bool {
        todo!()
    }

    /// Returns the left padded big-endian encoding of the group element.
    /// 
    /// The encoding follows Section 5.1.1 in the specs. 
    pub fn to_be_bytes_left_pad(&self, group: &Group) -> Vec<u8>{
        to_be_bytes_left_pad(&self.0, group.l_p())
    }
}

impl Group {
    /// Constructs a new group
    ///
    /// This function checks that modulus is prime, that the order is prime, and that generator is a valid, non-one, group element (and thus a generator)
    pub fn new(modulus: BigUint, cofactor: BigUint, generator: BigUint) -> Self {
        todo!()
    }

    pub fn new_unchecked(modulus: BigUint, cofactor: BigUint, generator: BigUint) -> Self {
        todo!()
    }

    /// Returns a uniform random group element
    pub fn random_group_elem(&self, csprng: &mut Csprng) -> GroupElement {
        todo!()
    }

    /// Returns generator `g` raised to the power of `x` mod `p`.
    pub fn g_exp(&self, x: &FieldElement) -> GroupElement {
        GroupElement(self.g.modpow(&x.0, &self.p))
    }

    /// Returns the order of the group
    pub fn order(&self) -> BigUint {
        todo!()
    }

    /// Returns a generator of the group
    pub fn generator(&self) -> GroupElement {
        todo!()
    }

    /// Returns the length of the byte array representation of `p`
    pub fn l_p(&self) -> usize {
        (cnt_bits_repr(&self.p) + 7) / 8
    }  
}

/// This function checks if the given group and field have the same order.
pub fn group_matches_field(group: &Group, field: &ScalarField) -> bool {
    todo!()
}
