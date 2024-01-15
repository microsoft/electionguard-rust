#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides wrappers around `BigUnit` to separate group and field elements in the code.

use crate::{csprng::Csprng, prime::is_prime, integer_util::{cnt_bits_repr, to_be_bytes_left_pad}};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};
use serde::{Serialize, Deserialize};
use std::mem;


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

    pub fn is_zero(&self) -> bool { BigUint::is_zero(&self.0) }

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
    /// The arguments are
    /// - self - a field element
    /// - field - the scalar field
    ///
    // Returns the inverse of self mod field.q iff gcd(self,q) == 1
    pub fn inv(&self, field: &ScalarField) -> Option<Self> {
        if field.q.is_zero() {
            return None;
        }
        let m = BigInt::from_biguint(Sign::Plus, field.q.clone());
        let mut t = (BigInt::zero(), BigInt::one());
        let mut r = (m.clone(), BigInt::from_biguint(Sign::Plus, self.0.clone()));
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
                return Some(FieldElement((t.0 + m).magnitude().clone()));
            }
            return Some(FieldElement(t.0.magnitude().clone()));
        }
    
        None
        
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
        self.0 < field.q
    }
}

impl ScalarField {
    /// Constructs a new scalar field from a given order.
    ///
    /// This function returns `None` if the given order is not prime.
    pub fn new(order: BigUint, csprng: &mut Csprng) -> Option<Self> {
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
        if group.p.is_zero() {
            return None;
        }
        let m = BigInt::from_biguint(Sign::Plus, group.p.clone());
        let mut t = (BigInt::zero(), BigInt::one());
        let mut r = (m.clone(), BigInt::from_biguint(Sign::Plus, self.0.clone()));
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
                return Some(GroupElement((t.0 + m).magnitude().clone()));
            }
            return Some(GroupElement(t.0.magnitude().clone()));
        }
    
        None
        
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
        //let order_as_field_elem = FieldElement(group.order());
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
}

impl Group {
    /// Constructs a new group
    ///
    /// This function checks that modulus is prime, that the order is prime, and that generator is a valid, non-one, group element (and thus a generator)
    pub fn new(modulus: BigUint, cofactor: BigUint, generator: BigUint, csprng: &mut Csprng) -> Option<Self> {
        if cofactor.is_zero(){
            return None;
        }
        let modulus_is_prime = is_prime(&modulus, csprng);
        let order = (modulus.clone() - BigUint::one()) / cofactor.clone();
        let order_is_prime = is_prime(&order, csprng);
        let gen_has_order_q = generator.modpow(&order, &modulus).is_one();
        let gen_is_valid = gen_has_order_q && !generator.is_one();
        let all_checks_passed  = modulus_is_prime && order_is_prime && gen_is_valid;
        if all_checks_passed {
            Some(Group {
                 p: modulus,
                 r: cofactor,
                 g: generator
                })
        } else {
            None
        }
    }

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
        let p = self.p.clone();
        let r = self.r.clone();
        let order = (p - BigUint::one()) / r;
        return order; 
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