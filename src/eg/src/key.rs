// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;

use num_bigint::BigUint;

use util::csprng::Csprng;

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
}
