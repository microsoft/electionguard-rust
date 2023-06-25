// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;
use std::fs;
use std::path::PathBuf;

use num_bigint::BigUint;

use num_traits::{Num, One};
use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

use crate::contest_selection::ContestSelectionCiphertext;
use crate::fixed_parameters::FixedParameters;

#[derive(Debug, Clone)]
pub enum AsymmetricKeyType {
    Public,
    Private,
}

#[derive(Debug, Clone)]
pub struct PublicKey(pub BigUint);

#[derive(Debug)]
pub struct PrivateKey {
    /// Integer secret, s < q
    #[allow(dead_code)] //? TODO: Remove this
    s: BigUint,

    /// Public key, K = g^s mod p
    public_key: PublicKey,
}

/// Serialize for PublicKey
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.0.to_str_radix(16).serialize(serializer)
    }
}

/// Deserialize for PublicKey
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match String::deserialize(deserializer) {
            Ok(s) => Ok(PublicKey(BigUint::from_str_radix(&s, 16).unwrap())),
            Err(e) => Err(e),
        }
    }
}

/// Serialize for PrivateKey
impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        (self.s.to_str_radix(16), &self.public_key).serialize(serializer)
    }
}

pub fn homomorphic_addition(
    ctxts: Vec<&Vec<ContestSelectionCiphertext>>,
    fixed_parameters: &FixedParameters,
) -> Vec<ContestSelectionCiphertext> {
    assert!(ctxts.len() > 0);

    eprintln!(
        "Starting homomorphic addition of {} ciphertexts",
        ctxts[0].len()
    );

    let mut result = <Vec<ContestSelectionCiphertext>>::new();
    (0..ctxts[0].len()).for_each(|_| {
        result.push(ContestSelectionCiphertext {
            ciphertext: Ciphertext {
                alpha: BigUint::from(0 as usize),
                beta: BigUint::from(0 as usize),
            },
            nonce: BigUint::from(0 as usize),
        });
    });

    (0..ctxts.len()).for_each(|i| {
        (0..result.len()).for_each(|j| {
            result[j].ciphertext.alpha = (&result[j].ciphertext.alpha
                * &ctxts[i][j].ciphertext.alpha)
                % fixed_parameters.p.as_ref();
            result[j].ciphertext.beta = (&result[j].ciphertext.beta * &ctxts[i][j].ciphertext.beta)
                % fixed_parameters.p.as_ref();
            result[j].nonce = (&result[j].nonce + &ctxts[i][j].nonce) % fixed_parameters.q.as_ref();
        });
    });
    result
}

impl PrivateKey {
    pub fn new(csprng: &mut Csprng, fixed_parameters: &FixedParameters) -> Self {
        // "Each guardian T_i generates an independent ElGamal public-private key pair by
        // generating a random integer secret s_i ∈ Zq
        let s = csprng.next_biguint_lt(fixed_parameters.q.borrow());

        // "and forming the public key K_i = g^s_i mod p."
        let k = fixed_parameters.g.modpow(&s, fixed_parameters.p.borrow());
        let public_key = PublicKey(k);

        PrivateKey { s, public_key }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn decrypt_check(
        &self,
        fixed_parameters: &FixedParameters,
        ct: Ciphertext,
        vote: usize,
    ) -> bool {
        let mut pt = ct.alpha.modpow(&self.s, fixed_parameters.p.borrow());
        pt = ct.beta
            * pt.modpow(
                (fixed_parameters.p.as_ref() - BigUint::from(2 as usize)).borrow(),
                fixed_parameters.p.borrow(),
            );
        pt = pt.modpow(&One::one(), fixed_parameters.p.borrow());
        pt == self
            .public_key
            .0
            .modpow(BigUint::from(vote).borrow(), fixed_parameters.p.borrow())
    }
}

impl PublicKey {
    pub fn from_json(json: &str) -> Self {
        serde_json::from_str(json).unwrap()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn decrypt_check_with(
        &self,
        fixed_parameters: &FixedParameters,
        ct: Ciphertext,
        vote: usize,
        nonce: &BigUint,
    ) -> bool {
        let mut pt = self.0.modpow(nonce, fixed_parameters.p.borrow());
        pt = ct.beta
            * pt.modpow(
                (fixed_parameters.p.as_ref() - BigUint::from(2 as usize)).borrow(),
                fixed_parameters.p.borrow(),
            );
        pt = pt.modpow(&One::one(), fixed_parameters.p.borrow());
        pt == self
            .0
            .modpow(BigUint::from(vote).borrow(), fixed_parameters.p.borrow())
    }

    pub fn new_from_file(path: &PathBuf) -> Self {
        match fs::read_to_string(path) {
            Ok(file) => match serde_json::from_str(&file) {
                Ok(key) => return key,
                Err(e) => panic!("Error reading public key from file: {}", e),
            },
            Err(e) => panic!("Error reading public key from file: {}", e),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::standard_parameters::STANDARD_PARAMETERS;

    #[test]
    fn test_key_generation() {
        let fixed_parameters = (*STANDARD_PARAMETERS).clone();
        let mut csprng = Csprng::new(&[0u8; 0]);

        let private_key = PrivateKey::new(&mut csprng, &fixed_parameters);

        let public_key: PublicKey = private_key.public_key().clone();

        assert!(&private_key.s < fixed_parameters.q.borrow());
        assert!(&public_key.0 < fixed_parameters.p.borrow());
    }

    #[test]
    fn test_encryption() {
        let fixed_parameters = (*STANDARD_PARAMETERS).clone();
        let mut csprng = Csprng::new(&[0u8; 0]);

        let private_key = PrivateKey::new(&mut csprng, &fixed_parameters);
        let public_key: PublicKey = private_key.public_key().clone();

        (0..10).for_each(|_| {
            let vote = csprng.next_u64() as usize % 2;
            let nonce = csprng.next_biguint_lt(fixed_parameters.q.borrow());
            let ct = public_key.encrypt_with(&fixed_parameters, &nonce, vote);

            assert!(private_key.decrypt_check(&fixed_parameters, ct.clone(), vote));
            assert!(public_key.decrypt_check_with(&fixed_parameters, ct, vote, nonce.borrow()));
        })
    }
}
