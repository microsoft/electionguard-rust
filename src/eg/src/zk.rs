// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides the implementation of the range proof [`ProofRange`] for [`Ciphertext`]s.
//! For more details see Section `3.3.5` of the Electionguard specification `2.0.0`. [TODO fix ref]

use serde::{Deserialize, Serialize};
use util::{
    algebra::{FieldElement, GroupElement, ScalarField},
    csrng::Csrng,
    vec1::HasIndexType,
};

use crate::{
    ciphertext::{Ciphertext, CiphertextIndex},
    hash::eg_h,
    nonce::NonceFE,
    pre_voting_data::PreVotingData,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRangeSingle {
    /// Challenge
    pub c: FieldElement,
    /// Response
    pub v: FieldElement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRange(Vec<ProofRangeSingle>);

impl HasIndexType for ProofRange {
    type IndexTypeParam = Ciphertext;
}

/// Same type as [`CiphertextIndex`], [`ContestOptionIndex`](crate::election_manifest::ContestOptionIndex), [`ContestDataFieldIndex`](crate::contest_data_fields_plaintexts::ContestDataFieldIndex), etc.
pub type ProofRangeIndex = CiphertextIndex;

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum ZkProofRangeError {
    #[error("It must be that 0 ≤ small_l ≤ big_l (here small_l={small_l} and big_l={big_l}).")]
    RangeNotSatisfied { small_l: usize, big_l: usize },
}

impl ProofRange {
    /// Computes the challenge for the range proof as specified in Equation `46`. [TODO fix ref]
    ///
    /// The arguments are
    /// - `pvd` - the pre voting data
    /// - `ct` - the ciphertext
    /// - `a` - the a vector of the commit message
    /// - `b` - the b vector of the commit message
    pub fn challenge(
        pre_voting_data: &PreVotingData,
        ct: &Ciphertext,
        a: &[GroupElement],
        b: &[GroupElement],
    ) -> FieldElement {
        let field = pre_voting_data
            .election_parameters()
            .fixed_parameters()
            .field();
        let group = pre_voting_data
            .election_parameters()
            .fixed_parameters()
            .group();

        // v = 0x21 | b(K,512) | b(alpha,4) | b(beta,512) | b(a_0,512) | ... | b(b_L,512) for standard parameters
        let mut v = vec![0x21];
        v.extend_from_slice(
            pre_voting_data
                .jvepk_k()
                .group_element
                .to_be_bytes_left_pad(group)
                .as_slice(),
        );
        v.extend_from_slice(ct.alpha.to_be_bytes_left_pad(group).as_slice());
        v.extend_from_slice(ct.beta.to_be_bytes_left_pad(group).as_slice());
        a.iter().for_each(|a_i| {
            v.extend_from_slice(a_i.to_be_bytes_left_pad(group).as_slice());
        });
        b.iter().for_each(|b_i| {
            v.extend_from_slice(b_i.to_be_bytes_left_pad(group).as_slice());
        });

        // Equation `46` [TODO fix ref]
        let c = eg_h(pre_voting_data.h_e(), &v);
        //? TODO can we use eg::hash::eg_h_q() for this?
        FieldElement::from_bytes_be(c.0.as_slice(), field)
    }

    /// Computes a [`ProofRange`] from given [`Ciphertext`] and encrypted `small_l`.
    ///
    /// The arguments are
    /// - `pre_voting_data` - pre-voting data
    /// - `csrng` - secure randomness generator
    /// - `ct` - the ciphertext
    /// - `small_l` - the encrypted number
    /// - `big_l` - the range bound
    pub fn new(
        pre_voting_data: &PreVotingData,
        csrng: &dyn Csrng,
        ct: &Ciphertext,
        nonce: &NonceFE,
        small_l: usize,
        big_l: usize,
    ) -> Result<Self, ZkProofRangeError> {
        if small_l > big_l {
            return Err(ZkProofRangeError::RangeNotSatisfied { small_l, big_l });
        }

        let field = pre_voting_data
            .election_parameters()
            .fixed_parameters()
            .field();
        let group = pre_voting_data
            .election_parameters()
            .fixed_parameters()
            .group();

        // Compute commit message and simulated challenges
        let u = (0..big_l + 1)
            .map(|_| field.random_field_elem(csrng))
            .collect::<Vec<FieldElement>>();
        let mut c = (0..big_l + 1)
            .map(|_| field.random_field_elem(csrng))
            .collect::<Vec<FieldElement>>();
        let a = (0..big_l + 1)
            .map(|j| group.g_exp(&u[j]))
            .collect::<Vec<GroupElement>>();
        let l_scalar = FieldElement::from(small_l, field);
        let mut t = u.clone();
        for j in 0..big_l + 1 {
            if j != small_l {
                let j_scalar = FieldElement::from(j, field);
                let c_prod = c[j].mul(&l_scalar.sub(&j_scalar, field), field);
                t[j] = t[j].add(&c_prod, field)
            }
        }
        let b = (0..big_l + 1)
            .map(|j| pre_voting_data.jvepk_k().group_element.exp(&t[j], group))
            .collect::<Vec<GroupElement>>();

        // Compute real challenge c_{small_l}
        let challenge = ProofRange::challenge(pre_voting_data, ct, &a, &b);
        c[small_l] = challenge;
        for j in 0..big_l + 1 {
            if j != small_l {
                c[small_l] = c[small_l].sub(&c[j], field)
            }
        }

        // Compute responses
        let v = (0..big_l + 1)
            .map(|j| u[j].sub(&c[j].mul(nonce.as_ref(), field), field))
            .collect::<Vec<FieldElement>>();

        Ok(ProofRange(
            (0..big_l + 1)
                .map(|j| ProofRangeSingle {
                    c: c[j].clone(),
                    v: v[j].clone(),
                })
                .collect(),
        ))
    }

    /// Verifies a [`ProofRange`] with respect to a given [`Ciphertext`] and context.
    ///
    /// The arguments are
    /// - `self` - the range proof
    /// - `pvd` - the pre-voting data
    /// - `ct` - the ciphertext
    /// - `big_l` - the range bound
    ///
    /// This is essentially Verification (5).
    pub fn verify(&self, pvd: &PreVotingData, ct: &Ciphertext, big_l: u32) -> bool {
        let field = pvd.election_parameters().fixed_parameters().field();
        let group = pvd.election_parameters().fixed_parameters().group();

        let Ok(big_l_usize) = TryInto::<usize>::try_into(big_l) else {
            return false;
        };

        // (5.1)
        let a = (0..big_l_usize + 1)
            .map(|j| {
                group
                    .g_exp(&self.0[j].v)
                    .mul(&ct.alpha.exp(&self.0[j].c, group), group)
            })
            .collect::<Vec<GroupElement>>();

        // (5.2)
        let w = (0..big_l_usize + 1)
            .map(|j| {
                let j_scalar = FieldElement::from(j, field);
                self.0[j].v.sub(&j_scalar.mul(&self.0[j].c, field), field)
            })
            .collect::<Vec<FieldElement>>();

        let b = (0..big_l_usize + 1)
            .map(|j| {
                let k_w = pvd.jvepk_k().group_element.exp(&w[j], group);
                let b_c = ct.beta.exp(&self.0[j].c, group);
                k_w.mul(&b_c, group)
            })
            .collect::<Vec<GroupElement>>();

        // (5.3)
        let c = Self::challenge(pvd, ct, &a, &b);

        // Verification check (5.A) alpha, beta are valid group elements
        if !ct.alpha.is_valid(group) || !ct.beta.is_valid(group) {
            return false;
        }

        for j in 0..big_l_usize + 1 {
            // Verification check (5.B) 0 <= c_j < 2^256
            // This is enforced by c_j being a valid field element (q < 2^256 for standard parameter)
            if !self.0[j].c.is_valid(field) {
                return false;
            }

            // Verification check (5.C) v_j is a valid field element
            if !self.0[j].v.is_valid(field) {
                return false;
            }
        }

        // Verification check (5.D)
        let rhs = self
            .0
            .iter()
            .fold(ScalarField::zero(), |acc, pf| acc.add(&pf.c, field));
        c == rhs
    }
}

/*
#[derive(Debug, Clone)]
pub struct ProofGuardian {
    pub c: Vec<BigUint>,
    pub v: Vec<BigUint>,
    pub capital_k: Vec<BigUint>,
}
impl struct ProofCorrectDecryption {}
Serialize for ProofGuardian
impl Serialize for ProofGuardian {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        (
            self.c
                .iter()
                .map(|x| x.to_str_radix(16))
                .collect::<Vec<String>>(),
            self.v
                .iter()
                .map(|x| x.to_str_radix(16))
                .collect::<Vec<String>>(),
            self.capital_k
                .iter()
                .map(|x| x.to_str_radix(16))
                .collect::<Vec<String>>(),
        )
            .serialize(serializer)
    }
}
// Deserialize for ProofGuardian
impl<'de> Deserialize<'de> for ProofGuardian {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        match <(Vec<String>, Vec<String>, Vec<String>)>::deserialize(deserializer) {
            Ok((c, v, capital_k)) => Ok(Self {
                c: c.iter()
                    .map(|x| BigUint::from_str_radix(x, 16).unwrap())
                    .collect(),
                v: v.iter()
                    .map(|x| BigUint::from_str_radix(x, 16).unwrap())
                    .collect(),
                capital_k: capital_k
                    .iter()
                    .map(|x| BigUint::from_str_radix(x, 16).unwrap())
                    .collect(),
            }),
            Err(e) => return Err(e),
        }
    }
}
impl ProofGuardian {
    pub fn from_json(json: &str) -> Self {
        serde_json::from_str(json).unwrap()
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
    pub fn challenge(
        fixed_parameters: &FixedParameters,
        h_p: HValue,
        i: u32,
        j: u32,
        capital_k_i_j: &BigUint,
        h_i_j: &BigUint,
    ) -> BigUint {
        let mut v = vec![0x10];
        v.extend_from_slice(i.to_be_bytes().as_slice());
        v.extend_from_slice(j.to_be_bytes().as_slice());
        v.extend_from_slice(capital_k_i_j.to_bytes_be().as_slice());
        v.extend_from_slice(h_i_j.to_bytes_be().as_slice());
        // Equation 11 [TODO fix ref]
        let c = eg_h(&h_p, &v);
        BigUint::from_bytes_be(c.0.as_slice()) % fixed_parameters.q.as_ref()
    }
    pub fn new(
        csrng: &dyn Csrng,
        fixed_parameters: &FixedParameters,
        h_p: HValue,
        zmulq: Arc<ZMulPrime>,
        i: u16,
        k: u16,
        capital_k_i: &[BigUint],
        a_i: &[BigUint],
    ) -> Self {
        let u = (0..k)
            .map(|_| ZMulPrimeElem::new_pick_random(zmulq.clone(), csrng))
            .collect::<Vec<ZMulPrimeElem>>();
        let h = u
            .iter()
            .map(|u_j| {
                fixed_parameters
                    .g
                    .modpow(&u_j.elem, fixed_parameters.p.borrow())
            })
            .collect::<Vec<BigUint>>();
        let mut c = <Vec<ZMulPrimeElem>>::new();
        let mut v = <Vec<ZMulPrimeElem>>::new();
        for j in 0..k {
            match ZMulPrimeElem::try_new(
                zmulq.clone(),
                Self::challenge(
                    fixed_parameters,
                    h_p,
                    i as u32,
                    j as u32,
                    &capital_k_i[j as u32],
                    &h[j as u32],
                ),
            ) {
                Some(x) => c.push(x),
                None => panic!("Challenge is not in ZmulPrime"),
            };
            v.push(&u[j as u32] - &(&c[j as u32] * &a_i[j as u32]));
        }
        ProofGuardian {
            c: c.iter().map(|x| x.elem.clone()).collect(),
            v: v.iter().map(|x| x.elem.clone()).collect(),
            capital_k: capital_k_i.to_vec(),
        }
    }
    /// Verification 2
    pub fn verify(&self, fixed_parameters: &FixedParameters, h_p: HValue, i: u16, k: u16) -> bool {
        // 2.1
        let h = (0..k)
            .map(|j| {
                let j = j as u32;
                fixed_parameters
                    .g
                    .modpow(&self.v[j], fixed_parameters.p.borrow())
                    * self.capital_k[j].modpow(&self.c[j], fixed_parameters.p.borrow())
                    % fixed_parameters.p.as_ref()
            })
            .collect::<Vec<BigUint>>();
        // let zmulp = Arc::new(ZMulPrime::new(fixed_parameters.p.clone()));
        // let zmulq = Arc::new(ZMulPrime::new(fixed_parameters.q.clone()));
        let mut verified = true;
        let zero = BigUint::from(0u8);
        // let one = BigUint::from(1u8);
        for j in 0..k {
            let j = j as u32;
            // 2.A
            verified &=
                (zero <= self.capital_k[j]) & (self.capital_k[j] < *fixed_parameters.p.borrow());
            verified &= self.capital_k[j]
                .modpow(fixed_parameters.q.borrow(), fixed_parameters.p.borrow())
                == One::one();
            // 2.B
            verified &= (zero <= self.v[j]) & (self.v[j] < *fixed_parameters.q.borrow());
            // 2.C
            verified &= self.c[j]
                == Self::challenge(
                    fixed_parameters,
                    h_p,
                    i as u32,
                    j,
                    &self.capital_k[j],
                    &h[j],
                );
        }
        verified
    }
}
*/
