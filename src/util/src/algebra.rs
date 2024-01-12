#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides wrappers around `BigUnit` to separate group and field elements in the code.

use crate::{csprng::Csprng, prime::is_prime};
use num_bigint::BigUint;

/// A field element, i.e. an element of `Z_q`.
pub struct FieldElement(BigUint);

/// The finite field `Z_q` of integers modulo q.
pub struct ScalarField {
    /// Subgroup order.
    pub q: BigUint,
}

impl FieldElement {
    /// Performs field addition modulo prime q.
    pub fn add(&self, other: &FieldElement, field: &ScalarField) -> FieldElement {
        FieldElement((&self.0 + &other.0) % &field.q)
    }

    /// Performs field subtraction modulo prime q.
    pub fn sub(&self, other: &FieldElement, field: &ScalarField) -> FieldElement {
        if self.0 > other.0 {
            FieldElement((&self.0 - &other.0) % &field.q)
        } else {
            FieldElement(&field.q - ((&other.0 - &self.0) % &field.q))
        }
    }

    /// Performs field multiplication modulo prime q.
    pub fn mul(&self, other: &FieldElement, field: &ScalarField) -> FieldElement {
        FieldElement((&self.0 * &other.0) % &field.q)
    }

    /// Computes the multiplicative inverse of a field element if it exists
    pub fn inv(&self, field: &ScalarField) -> Option<FieldElement> {
        todo!()
    }

    /// Returns the left padded big-endian encoding of the field element.
    /// 
    /// The encoding follows Section 5.1.2 in the specs. 
    pub fn to_be_bytes_left_pad(&self, field: &ScalarField) -> Vec<u8>{

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
    pub fn order() -> BigUint {
        todo!()
    }
}

/// A group element, i.e. an element of `Z_p^r`.
pub struct GroupElement(BigUint);

/// The group `Z_p^r`, a multiplicative subgroup of `Z_p`.
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
    pub fn to_be_bytes_left_pad(&self, field: &ScalarField) -> Vec<u8>{

    }
}

impl Group {
    /// Constructs a new group
    ///
    /// This function checks that modulus is prime, that the order is prime, and that generator is a valid, non-one, group element (and thus a generator)
    pub fn new(modulus: &BigUint, cofactor: &BigUint, generator: &BigUint) -> Self {
        todo!()
    }

    pub fn new_unchecked(modulus: &BigUint, cofactor: &BigUint, generator: &BigUint) -> Self {
        todo!()
    }

    /// Returns a uniform random group element
    pub fn random_group_elem(&self, csprng: &mut Csprng) -> GroupElement {
        todo!()
    }

    /// Returns the order of the group
    pub fn order() -> BigUint {
        todo!()
    }

    /// Returns a generator of the group
    pub fn generator() -> GroupElement {
        todo!()
    }
}

/// This function checks if the given group and field have the same order.
pub fn group_matches_field(group: &Group, field: &ScalarField) -> bool {
    todo!()
}
