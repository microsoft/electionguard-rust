#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides wrappers around `BigUnit` to separate group and field elements in the code.

use crate::{csprng::Csprng, prime::is_prime, integer_util::{cnt_bits_repr, to_be_bytes_left_pad, mod_inverse}};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Serialize, Deserialize};

/// A field element, i.e. an element of `Z_q`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldElement(BigUint);

/// The finite field `Z_q` of integers modulo q.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScalarField {
    /// Subgroup order.
    q: BigUint,
}

impl FieldElement {

    pub fn is_zero(&self) -> bool { BigUint::is_zero(&self.0) }

    pub fn from_biguint(x: BigUint, field: &ScalarField) -> Self {
        FieldElement(x % &field.q)
    }

    pub fn from_bytes_be(x: &[u8], field: &ScalarField) -> Self {
        let x_int = BigUint::from_bytes_be(x);
        FieldElement(x_int % &field.q)
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
    /// The arguments are
    /// - self - a field element
    /// - field - the scalar field
    ///
    // Returns the inverse of self mod field.q iff gcd(self,q) == 1
    pub fn inv(&self, field: &ScalarField) -> Option<Self> {
        match mod_inverse(&self.0,&field.q) {
            Some(x) => Some(FieldElement(x)),
            None => None,
        } 
    }

    /// Returns the left padded big-endian encoding of the field element.
    /// 
    /// The encoding follows Section 5.1.2 in the specs. 
    pub fn to_be_bytes_left_pad(&self, field: &ScalarField) -> Vec<u8>{
        to_be_bytes_left_pad(&self.0, field.l_q())
    }

    /// Checks if the element is a valid member of the given field.
    ///
    /// This method return true iff 0 <= self < field.q.
    pub fn is_valid(&self, field: &ScalarField) -> bool {
        // It is enough to check the upper bound as self.0 is unsigned.
        self.0 < field.q
    }

    pub fn remove_at_the_end_biguint(&self) -> BigUint {
        self.0.clone()
    }
}

impl ScalarField {
    /// Constructs a new scalar field from a given order.
    ///
    /// This function returns `None` if the given order is not prime.
    pub fn new(order: BigUint, csprng: &mut Csprng) -> Option<Self> {
        let f = ScalarField { q: order };
        if f.is_valid(csprng) {
            return Some(f)
        }
        None
    }

    /// The function validates the given field.
    /// 
    /// That is the function checks that the modulus is prime.
    pub fn is_valid(&self, csprng: &mut Csprng) -> bool {
        is_prime(&self.q, csprng)
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
        self.q.clone()
    }

    /// Returns the length of the byte array representation of `q`
    pub fn l_q(&self) -> usize {
        (cnt_bits_repr(&self.q) + 7) / 8
    }
}

/// A group element, i.e. an element of `Z_p^r`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupElement(BigUint);

/// The group `Z_p^r`, a multiplicative subgroup of `Z_p`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    /// Prime modulus.
    p: BigUint,
    /// Cofactor of q in p − 1.
    r: BigUint,
    /// Subgroup generator.
    g: BigUint,
}

impl GroupElement {
    /// Performs group operation modulo prime p.
    pub fn mul(&self, other: &GroupElement, group: &Group) -> GroupElement {
        GroupElement((&self.0 * &other.0) % &group.p)
    }

    /// Computes the multiplicative inverse of a group element if it exists
    /// The arguments are
    /// - self - a group element
    /// - group - the group
    ///
    // Returns the inverse of self mod field.q iff gcd(self,q) == 1
    pub fn inv(&self, group: &Group) -> Option<Self> {
        match mod_inverse(&self.0,&group.p) {
            Some(x) => Some(GroupElement(x)),
            None => None,
        } 
    }

    /// Computes the `exponent`-power of the given group element, where exponent is a BigUint.
    pub fn pow(&self, exponent: &BigUint, group: &Group) -> GroupElement {
        GroupElement(self.0.modpow(&exponent, &group.p))
    }
    
    /// Computes the `exponent`-power of the given group element, where exponent is a FieldElement.
    pub fn exp(&self, exponent: &FieldElement, group: &Group) -> GroupElement {
        GroupElement(self.0.modpow(&exponent.0, &group.p))
    }
    
    /// Checks if the element is a valid member of the given group.
    ///
    /// This method return true iff 0 <= self < group.p and self^group.order() % p == 1
    pub fn is_valid(&self, group: &Group) -> bool {
        // It is enough to check the upper bound as self.0 is unsigned.
        let elem_less_than_p = self.0 < group.p;
        let elem_has_order_q = self.pow(&group.order(), group).0.is_one();
        elem_less_than_p && elem_has_order_q
    }

    /// Returns the left padded big-endian encoding of the group element.
    /// 
    /// The encoding follows Section 5.1.1 in the specs. 
    pub fn to_be_bytes_left_pad(&self, group: &Group) -> Vec<u8>{
        to_be_bytes_left_pad(&self.0, group.l_p())
    }

    pub fn remove_at_the_end_biguint(&self) -> BigUint {
        self.0.clone()
    }
}

impl Group {
    /// Constructs a new group
    ///
    /// This function checks that the group is valid.
    pub fn new(modulus: BigUint, cofactor: BigUint, generator: BigUint, csprng: &mut Csprng) -> Option<Self> {
        let group = Group {
            p: modulus,
            r: cofactor,
            g: generator
           };
        if group.is_valid(csprng) {
            return Some(group)
        }
        None
    }

    /// This function checks that the given group is valid.
    /// 
    /// That is it checks that 
    /// - the modulus is prime
    /// - the order is prime
    /// - the generator is a proper generator
    /// - the order does not divide the co-factor
    /// - the co-factor is non-zero
    pub fn is_valid(&self, csprng: &mut Csprng) -> bool { 
        if self.r.is_zero(){
            return false
        }
        if !is_prime(&self.p, csprng) {
            return false
        }
        let order = (&self.p - BigUint::one()) / &self.r;
        if !is_prime(&order, csprng) {
            return false
        }
        // This ensures that the order of generator is at most `order`
        if !self.g.modpow(&order, &self.p).is_one() {
            return false
        }
        // If generator is not one (and `order` is prime) => order of generator is `order`
        if !self.g.is_one() {
            return false
        }
        // `order` should not divide `cofactor`
        if (&self.r % order).is_zero() {
            return false
        } 
        true       
    }

    /// Constructs a new group without validity check
    pub fn new_unchecked(modulus: BigUint, cofactor: BigUint, generator: BigUint) -> Self {
        Group {
            p: modulus,
            r: cofactor,
            g: generator
           }
    }

    /// Returns a uniform random group element
    pub fn random_group_elem(&self, csprng: &mut Csprng) -> GroupElement {
        let q = self.order();
        let field_elem = FieldElement(csprng.next_biguint_lt(&q));
        let group_elem = self.g_exp(&field_elem);
        group_elem
    }

    /// Returns generator `g` raised to the power of `x` mod `p`.
    pub fn g_exp(&self, x: &FieldElement) -> GroupElement {
        GroupElement(self.g.modpow(&x.0, &self.p))
    }

    /// Returns the order of the group
    pub fn order(&self) -> BigUint {
        (&self.p - BigUint::one()) / &self.r
    }

    /// Returns a generator of the group
    pub fn generator(&self) -> GroupElement {
        GroupElement(self.g.clone())
    }

    /// Returns the length of the byte array representation of `p`
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
 mod test {
    use num_bigint::BigUint;

    #[test]
    fn test_1() {
    }
}