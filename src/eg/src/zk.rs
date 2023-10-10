// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, prime::BigUintPrime};

use crate::{
    election_record::PreVotingData, hash::eg_h, index::Index, joint_election_public_key::Ciphertext,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRangeSingle {
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub c: BigUint,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub v: BigUint,
}

/// A 1-based index of a [`ProofRange`] in the order it is stored in the [`crate::contest_encrypted::ContestEncrypted`].
pub type ProofRangeIndex = Index<ProofRange>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRange(Vec<ProofRangeSingle>);

impl ProofRange {
    pub fn challenge(
        pvd: &PreVotingData,
        ct: &Ciphertext,
        a: &[BigUint],
        b: &[BigUint],
    ) -> BigUint {
        let mut v = vec![0x21];

        v.extend_from_slice(
            pvd.public_key
                .joint_election_public_key
                .to_bytes_be()
                .as_slice(),
        );
        v.extend_from_slice(ct.alpha.to_bytes_be().as_slice());
        v.extend_from_slice(ct.beta.to_bytes_be().as_slice());

        a.iter().for_each(|a_i| {
            v.extend_from_slice(a_i.to_bytes_be().as_slice());
        });
        b.iter().for_each(|b_i| {
            v.extend_from_slice(b_i.to_bytes_be().as_slice());
        });

        // Equation 25
        let c = eg_h(&pvd.hashes_ext.h_e, &v);
        BigUint::from_bytes_be(c.0.as_slice()) % pvd.parameters.fixed_parameters.q.as_ref()
    }

    pub fn new(
        pvd: &PreVotingData,
        csprng: &mut Csprng,
        q: &BigUintPrime,
        ct: &Ciphertext,
        small_l: usize,
        big_l: usize,
    ) -> Self {
        let mut c: Vec<BigUint>;
        let mut v = <Vec<BigUint>>::new();

        let u = (0..big_l + 1)
            .map(|_| q.random_group_elem(csprng))
            .collect::<Vec<BigUint>>();
        c = (0..big_l + 1)
            .map(|_| q.random_group_elem(csprng))
            .collect::<Vec<BigUint>>();

        let a: Vec<BigUint> = (0..big_l + 1)
            .map(|j| {
                pvd.parameters
                    .fixed_parameters
                    .g
                    .modpow(&u[j], pvd.parameters.fixed_parameters.p.borrow())
            })
            .collect();

        let mut t = u.clone();
        for j in 0..big_l + 1 {
            if j != small_l {
                t[j] = q.subtract_group_elem(
                    &q.add_group_elem(&t[j], &(&c[j] * &BigUint::from(small_l))),
                    &(&c[j] * &BigUint::from(j)),
                );
            }
        }

        let b: Vec<BigUint> = (0..big_l + 1)
            .map(|j| {
                pvd.public_key
                    .joint_election_public_key
                    .modpow(&t[j], pvd.parameters.fixed_parameters.p.borrow())
            })
            .collect();

        let challenge = ProofRange::challenge(pvd, ct, &a, &b);
        c[small_l] = challenge;
        for j in 0..big_l + 1 {
            if j != small_l {
                // c[small_l] = &c[small_l] - &c[j];
                c[small_l] = q.subtract_group_elem(&c[small_l], &c[j]);
            }
        }
        for j in 0..big_l + 1 {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            v.push(q.subtract_group_elem(&u[j], &(&c[j] * ct.nonce.as_ref().unwrap())));
            // v.push(&u[j] - &(&c[j] * ct.nonce.as_ref().unwrap()));
        }

        ProofRange(
            (0..big_l + 1)
                .map(|j| ProofRangeSingle {
                    c: c[j].clone(),
                    v: v[j].clone(),
                })
                .collect(),
        )
    }

    /// Verification 4
    pub fn verify(&self, pvd: &PreVotingData, ct: &Ciphertext, big_l: usize) -> bool {
        let a = (0..big_l + 1)
            .map(|j| {
                (pvd.parameters
                    .fixed_parameters
                    .g
                    .modpow(&self.0[j].v, pvd.parameters.fixed_parameters.p.borrow())
                    * ct.alpha
                        .modpow(&self.0[j].c, pvd.parameters.fixed_parameters.p.borrow()))
                    % pvd.parameters.fixed_parameters.p.as_ref()
            })
            .collect::<Vec<_>>();

        let mut w = <Vec<BigUint>>::with_capacity(big_l + 1);
        for j in 0..big_l + 1 {
            w.push(self.0[j].v.clone());
            w[j] = pvd
                .parameters
                .fixed_parameters
                .q
                .subtract_group_elem(&w[j], &(&self.0[j].c * &BigUint::from(j)));
        }

        let b = (0..big_l + 1)
            .map(|j| {
                (pvd.public_key
                    .joint_election_public_key
                    .modpow(&w[j], pvd.parameters.fixed_parameters.p.borrow())
                    * ct.beta
                        .modpow(&self.0[j].c, pvd.parameters.fixed_parameters.p.borrow()))
                    % pvd.parameters.fixed_parameters.p.as_ref()
            })
            .collect::<Vec<_>>();

        let c = Self::challenge(pvd, ct, &a, &b);

        let mut rhs = BigUint::from(0u8);
        for e in self.0.iter() {
            rhs += &e.c;
        }

        rhs %= pvd.parameters.fixed_parameters.q.as_ref();

        c == rhs

        // 4.A
        // TODO

        // 4.B
        // TODO

        // 4.C
        // TODO
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
        i: usize,
        j: usize,
        capital_k_i_j: &BigUint,
        h_i_j: &BigUint,
    ) -> BigUint {
        let mut v = vec![0x10];
        v.extend_from_slice(i.to_be_bytes().as_slice());
        v.extend_from_slice(j.to_be_bytes().as_slice());
        v.extend_from_slice(capital_k_i_j.to_bytes_be().as_slice());
        v.extend_from_slice(h_i_j.to_bytes_be().as_slice());
        // Equation 11
        let c = eg_h(&h_p, &v);
        BigUint::from_bytes_be(c.0.as_slice()) % fixed_parameters.q.as_ref()
    }
    pub fn new(
        csprng: &mut Csprng,
        fixed_parameters: &FixedParameters,
        h_p: HValue,
        zmulq: Rc<ZMulPrime>,
        i: u16,
        k: u16,
        capital_k_i: &[BigUint],
        a_i: &[BigUint],
    ) -> Self {
        let u = (0..k)
            .map(|_| ZMulPrimeElem::new_pick_random(zmulq.clone(), csprng))
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
                    i as usize,
                    j as usize,
                    &capital_k_i[j as usize],
                    &h[j as usize],
                ),
            ) {
                Some(x) => c.push(x),
                None => panic!("Challenge is not in ZmulPrime"),
            };
            v.push(&u[j as usize] - &(&c[j as usize] * &a_i[j as usize]));
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
                let j = j as usize;
                fixed_parameters
                    .g
                    .modpow(&self.v[j], fixed_parameters.p.borrow())
                    * self.capital_k[j].modpow(&self.c[j], fixed_parameters.p.borrow())
                    % fixed_parameters.p.as_ref()
            })
            .collect::<Vec<BigUint>>();
        // let zmulp = Rc::new(ZMulPrime::new(fixed_parameters.p.clone()));
        // let zmulq = Rc::new(ZMulPrime::new(fixed_parameters.q.clone()));
        let mut verified = true;
        let zero = BigUint::from(0u8);
        // let one = BigUint::from(1u8);
        for j in 0..k {
            let j = j as usize;
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
                    i as usize,
                    j,
                    &self.capital_k[j],
                    &h[j],
                );
        }
        verified
    }
}
*/
