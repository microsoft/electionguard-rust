// Copyright (C) Microsoft Corporation. All rights reserved.



use num_bigint::BigUint;
use crate::{prime::is_prime, csprng::Csprng};


#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldElement(BigUint);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GroupElement(BigUint);


pub struct ScalarField {
    /// Subgroup order.
    pub q: BigUint,
}

pub struct Group {
    /// Prime modulus.
    pub p: BigUint,

    /// Cofactor of q in p − 1.
    pub r: BigUint,

    /// Subgroup generator.
    pub g: BigUint,
}

impl FieldElement {

    // Performs field addition modulo prime q.
    pub fn add(&self, other: &FieldElement, field: &ScalarField) -> FieldElement {
        FieldElement((&self.0 + &other.0) % &field.q)
    }

    // Performs field subtraction modulo prime q.
    pub fn subtract(&self, other: &FieldElement, field: &ScalarField) -> FieldElement {
        if self.0 > other.0 {
            FieldElement((&self.0 - &other.0) % &field.q)
        } else {
            FieldElement(&field.q - ((&other.0 - &self.0) % &field.q))
        }
    }

    // Performs field multiplication modulo prime q.
    pub fn multiply(&self, other: &FieldElement, field: &ScalarField) -> FieldElement {
        FieldElement((&self.0 * &other.0) % &field.q)
    }

}

impl ScalarField {
    
    // Constructor for ScalarField
    pub fn new(order: BigUint, csprng: &mut Csprng) -> Option<Self> {
        if is_prime(&order, csprng) {
            Some(ScalarField { q: order })
        } else {
            None
        }
    }
    
    // Constructor for ScalarField, but does not check that the input is prime.
    pub fn new_unchecked(order: BigUint) -> Self {
        ScalarField { q: order }
    }

    // ASK_DT: Do we need this?
    // Selects a random prime 2^(bits - 1) <= p < 2^bits
    #[allow(clippy::panic)]
    pub fn new_random_prime(bits: usize, csprng: &mut Csprng) -> ScalarField {
        todo!()
    }

    // Returns a random field element from [0,q).
    pub fn random_field_elem(&self, csprng: &mut Csprng) -> FieldElement {
        FieldElement(csprng.next_biguint_lt(&self.q))
    }

}

impl GroupElement {

    // ASK_DT: should this be removed because group is multiplicative?
    // Performs group addition modulo prime p.
    pub fn add(&self, other: &GroupElement, group: &Group) -> GroupElement {
        GroupElement((&self.0 + &other.0) % &group.p)
    }

    // ASK_DT: should this be removed because group is multiplicative?
    // Performs group subtraction modulo prime p.
    pub fn subtract(&self, other: &GroupElement, group: &Group) -> GroupElement {
        if self.0 > other.0 {
            GroupElement((&self.0 - &other.0) % &group.p)
        } else {
            GroupElement(&group.p - ((&other.0 - &self.0) % &group.p))
        }
    }

    // Performs group operation modulo prime p.
    pub fn multiply(&self, other: &GroupElement, group: &Group) -> GroupElement {
        GroupElement((&self.0 * &other.0) % &group.p)
    }

}

impl Group {
    
    // ASK_DT: this does not necessarily return a group element?!
    // Returns a random number chosen uniformly from 0 <= n < p.
    pub fn random_group_elem(&self, csprng: &mut Csprng) -> GroupElement {
        GroupElement(csprng.next_biguint_lt(&self.p))
    }

}
