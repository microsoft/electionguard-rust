// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

use util::{
    csprng::Csprng,
    integer_util::cnt_bits_repr,
    prime::{is_prime, BigUintPrime},
};

// "Nothing up my sleeve" numbers for use in fixed parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NumsNumber {
    // The Euler-Mascheroni constant γ =~ 0.577215664901532...
    // Binary expansion: (0.)1001001111000100011001111110...
    // https://oeis.org/A104015
    EulerMascheroniConstant,

    // The natural logarithm of 2.
    // Binary expansion: (0.)1011000101110010000101111111...
    //                          B   1   7   2   1   7   F...
    // https://oeis.org/A068426
    Ln2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedParameterGenerationParameters {
    pub q_bits_total: usize,
    pub p_bits_total: usize,
    pub p_bits_msb_fixed_1: usize,
    pub p_middle_bits_source: NumsNumber,
    pub p_bits_lsb_fixed_1: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedParameters {
    /// Version of the ElectionGuard to which these parameters conform.
    /// E.g., `Some([2, 0])` for v2.0 and `Some([1, 55])` for v1.55.
    /// `None` means the parameters may not conform to any version of the ElectionGuard spec.
    pub opt_version: Option<[usize; 2]>,

    /// Parameters used to generate the parameters.
    pub generation_parameters: FixedParameterGenerationParameters,

    /// Prime modulus.
    pub p: BigUintPrime,

    /// Subgroup order.
    pub q: BigUintPrime,

    /// Cofactor of q in p − 1.
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub r: BigUint,

    /// Subgroup generator.
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub g: BigUint,
}

impl FixedParameters {
    /// Verifies the parameters meet some of the key validity requirements.
    #[allow(clippy::nonminimal_bool)]
    pub fn verify(&self, csprng: &mut Csprng) -> bool {
        let q: &BigUint = self.q.borrow();
        let p: &BigUint = self.p.borrow();

        //TODO Maybe check that the parameters are consistent with the spec version
        //TODO verify p_bits_msb_fixed_1
        //TODO verify p_middle_bits_source
        //TODO verify p_bits_lsb_fixed_1

        // p is a prime of the requested number of bits
        if !is_prime(p, csprng) {
            return false;
        }
        if cnt_bits_repr(p) != self.generation_parameters.p_bits_total {
            return false;
        }

        // q is a prime of the requested number of bits
        if !is_prime(q, csprng) {
            return false;
        }
        if cnt_bits_repr(q) != self.generation_parameters.q_bits_total {
            return false;
        }

        // q < (p - 1)
        if !(q < &(p - 1_u8)) {
            return false;
        }

        // r = (p − 1)/q
        if !(self.r == ((p - 1_u8) / q)) {
            return false;
        }

        // q is not a divisor of r = (p − 1)/q
        let r: &BigUint = self.r.borrow();
        if (r % q).is_zero() {
            return false;
        }

        // g is in Zmodp and not 1
        let g: &BigUint = self.g.borrow();
        if !(&BigUint::one() < g) {
            return false;
        }
        if !(g < p) {
            return false;
        }

        true
    }
}
