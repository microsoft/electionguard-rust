// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;

use anyhow::{bail, Result};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

use util::{
    csprng::Csprng,
    integer_util::{cnt_bits_repr, to_be_bytes_left_pad},
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
    /// The length of the byte array representation of p.
    pub fn l_p_bytes(&self) -> usize {
        let p: &BigUint = self.p.borrow();
        (cnt_bits_repr(p) + 7) / 8
    }

    /// The length of the byte array representation of q.
    pub fn l_q_bytes(&self) -> usize {
        let q: &BigUint = self.q.borrow();
        (cnt_bits_repr(q) + 7) / 8
    }

    /// Converts a `BigUint` to a big-endian byte array of the correct length for `mod p`.
    pub fn biguint_to_be_bytes_len_p(&self, u: &BigUint) -> Vec<u8> {
        to_be_bytes_left_pad(&u, self.l_p_bytes())
    }

    /// Converts a `BigUint` to a big-endian byte array of the correct length for `mod q`.
    pub fn biguint_to_be_bytes_len_q(&self, u: &BigUint) -> Vec<u8> {
        to_be_bytes_left_pad(&u, self.l_q_bytes())
    }

    /// Verifies that the `FixedParameters` meet some basic validity requirements.
    #[allow(clippy::nonminimal_bool)]
    pub fn verify(&self, csprng: &mut Csprng) -> Result<()> {
        let q: &BigUint = self.q.borrow();
        let p: &BigUint = self.p.borrow();

        //TODO Maybe check that the parameters are consistent with the spec version
        //TODO verify p_bits_msb_fixed_1
        //TODO verify p_middle_bits_source
        //TODO verify p_bits_lsb_fixed_1

        // p is a prime of the requested number of bits
        if !is_prime(p, csprng) {
            bail!("Fixed parameters: p is not prime");
        }

        if cnt_bits_repr(p) != self.generation_parameters.p_bits_total {
            bail!("Fixed parameters: p wrong number of bits");
        }

        // q is a prime of the requested number of bits
        if !is_prime(q, csprng) {
            bail!("Fixed parameters: q is not prime");
        }
        if cnt_bits_repr(q) != self.generation_parameters.q_bits_total {
            bail!("Fixed parameters: q wrong number of bits");
        }

        // q < (p - 1)
        if !(q < &(p - 1_u8)) {
            bail!("Fixed parameters failed check: q < (p - 1)");
        }

        // r = (p − 1)/q
        if !(self.r == ((p - 1_u8) / q)) {
            bail!("Fixed parameters failed check: r = (p − 1)/q");
        }

        // q is not a divisor of r = (p − 1)/q
        let r: &BigUint = self.r.borrow();
        if (r % q).is_zero() {
            bail!("Fixed parameters failed check: q is not a divisor of r = (p − 1)/q");
        }

        // g is in Zmodp and not 0 or 1
        let g: &BigUint = self.g.borrow();
        if !(&BigUint::one() < g && g < p) {
            bail!("Fixed parameters failed check: g is in Zmodp and not 0 or 1");
        }
        if !(g < p) {
            bail!("Fixed parameters failed check: g < p");
        }

        Ok(())
    }
}
