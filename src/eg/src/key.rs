// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;
use std::ops;

use num_bigint::BigUint;

use num_traits::One;
use util::csprng::Csprng;

use crate::ballot::CiphertextContestSelection;
use crate::fixed_parameters::FixedParameters;

#[derive(Clone)]
pub struct PublicKey(pub BigUint);

#[derive(Clone)]
pub struct PrivateKey {
    /// Integer secret, s < q
    s: BigUint,

    /// Public key, K = g^s mod p
    public_key: PublicKey,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ciphertext(pub BigUint, pub BigUint);

pub fn homomorphic_addition(
    ctxts: Vec<&Vec<CiphertextContestSelection>>,
    fixed_parameters: &FixedParameters,
) -> Vec<CiphertextContestSelection> {
    assert!(ctxts.len() > 0);

    eprintln!(
        "Starting homomorphic addition of {} ciphertexts",
        ctxts[0].len()
    );

    let mut result = <Vec<CiphertextContestSelection>>::new();
    (0..ctxts[0].len()).for_each(|i| {
        result.push(CiphertextContestSelection {
            label: ctxts[0][i].label.clone(),
            ciphertext: Ciphertext(BigUint::from(0 as usize), BigUint::from(0 as usize)),
            nonce: BigUint::from(0 as usize),
        });
    });

    (0..ctxts.len()).for_each(|i| {
        (0..result.len()).for_each(|j| {
            result[j].ciphertext.0 =
                (&result[j].ciphertext.0 * &ctxts[i][j].ciphertext.0) % fixed_parameters.p.as_ref();
            result[j].ciphertext.1 =
                (&result[j].ciphertext.1 * &ctxts[i][j].ciphertext.1) % fixed_parameters.p.as_ref();
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
        let mut pt = ct.0.modpow(&self.s, fixed_parameters.p.borrow());
        pt = ct.1
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
    pub fn encrypt_with(
        &self,
        fixed_parameters: &FixedParameters,
        nonce: &BigUint,
        vote: usize,
    ) -> Ciphertext {
        let c1 = fixed_parameters
            .g
            .modpow(&nonce, fixed_parameters.p.borrow());
        let c2 = self.0.modpow(&(nonce + vote), fixed_parameters.p.borrow());
        Ciphertext(c1, c2)
    }

    pub fn decrypt_check_with(
        &self,
        fixed_parameters: &FixedParameters,
        ct: Ciphertext,
        vote: usize,
        nonce: &BigUint,
    ) -> bool {
        let mut pt = self.0.modpow(nonce, fixed_parameters.p.borrow());
        pt = ct.1
            * pt.modpow(
                (fixed_parameters.p.as_ref() - BigUint::from(2 as usize)).borrow(),
                fixed_parameters.p.borrow(),
            );
        pt = pt.modpow(&One::one(), fixed_parameters.p.borrow());
        pt == self
            .0
            .modpow(BigUint::from(vote).borrow(), fixed_parameters.p.borrow())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::standard_parameters::STANDARD_PARAMETERS;

    #[test]
    fn test_key_generation() {
        let fixed_parameters = (*STANDARD_PARAMETERS).clone();
        let mut csprng = Csprng::new(12345);

        let private_key = PrivateKey::new(&mut csprng, &fixed_parameters);

        let public_key: PublicKey = private_key.public_key().clone();

        assert!(&private_key.s < fixed_parameters.q.borrow());
        assert!(&public_key.0 < fixed_parameters.p.borrow());
    }

    #[test]
    fn test_encryption() {
        let fixed_parameters = (*STANDARD_PARAMETERS).clone();
        let mut csprng = Csprng::new(12345);

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
