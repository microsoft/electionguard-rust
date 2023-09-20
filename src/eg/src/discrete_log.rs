// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::collections::HashMap;

use num_bigint::BigUint;

pub struct DiscreteLog(pub HashMap<BigUint, u32>);

/// Returns the multiplicative inverse of a mod p where p is prime and (a, p) are co-prime.
fn mul_inv(a: &BigUint, p: &BigUint) -> BigUint {
    a.modpow(&(p - BigUint::from(2u8)), p)
}

impl DiscreteLog {
    /// Constructs a new pre-computation table.
    pub fn new(base: &BigUint, modulus: &BigUint) -> DiscreteLog {
        let mut hmap = HashMap::new();
        let mut k = BigUint::from(1u8);
        for j in 0..(1 << 16) {
            hmap.insert(k.clone(), j);
            k = (k * base) % modulus;
        }
        DiscreteLog(hmap)
    }

    /// Uses the Baby-step giant-step algorithm.
    pub fn find(&self, base: &BigUint, modulus: &BigUint, y: &BigUint) -> Option<BigUint> {
        let mut gamma = y.clone();
        let m = (1 << 16) as u32;
        let alpha_to_minus_m = mul_inv(&base.modpow(&BigUint::from(m), modulus), modulus);
        for i in 0..m {
            match self.0.get(&gamma) {
                Some(j) => {
                    return Some(BigUint::from(i * m + j));
                }
                None => {
                    gamma = (gamma * &alpha_to_minus_m) % modulus;
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Borrow;

    use util::csprng::Csprng;

    use crate::standard_parameters::STANDARD_PARAMETERS;

    use super::*;

    #[test]
    fn test_mulinv() {
        let mut csprng = Csprng::new(&[0u8]);
        let fixed_parameters = &STANDARD_PARAMETERS;

        for _ in 0..10 {
            let i = csprng.next_biguint_lt(fixed_parameters.p.borrow());
            let j = mul_inv(&i, fixed_parameters.p.as_ref());
            assert_eq!((i * j) % fixed_parameters.p.as_ref(), BigUint::from(1u8));
        }
    }

    #[test]
    fn test_dlog() {
        let mut csprng = Csprng::new(&[0u8]);
        let fixed_parameters = &STANDARD_PARAMETERS;
        let h = csprng.next_biguint_lt(fixed_parameters.p.borrow());
        let dl = DiscreteLog::new(&h, fixed_parameters.p.as_ref());

        for _ in 0..10 {
            let i = csprng.next_u32();
            let y = h.modpow(&BigUint::from(i), fixed_parameters.p.as_ref());
            assert_eq!(
                dl.find(&h, fixed_parameters.p.as_ref(), &y).unwrap(),
                BigUint::from(i)
            );
        }
    }
}
