use std::borrow::Borrow;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

use crate::{discrete_log::DiscreteLog, fixed_parameters::FixedParameters};

/// A commitment to a value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment(
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub BigUint,
);

impl Commitment {
    pub fn new(
        csprng: &mut Csprng,
        fixed_parameters: &FixedParameters,
        ck: &BigUint,
        m: &BigUint,
    ) -> (BigUint, Commitment) {
        let r = csprng.next_biguint_lt(fixed_parameters.q.borrow());
        let com = Commitment(
            fixed_parameters.g.modpow(&r, fixed_parameters.p.borrow())
                * ck.modpow(m, fixed_parameters.p.borrow())
                % fixed_parameters.p.as_ref(),
        );
        (r, com)
    }

    pub fn verify(
        &self,
        fixed_parameters: &FixedParameters,
        ck: &BigUint,
        m: &BigUint,
        r: &BigUint,
    ) -> bool {
        self.0
            == fixed_parameters.g.modpow(r, fixed_parameters.p.borrow())
                * ck.modpow(m, fixed_parameters.p.borrow())
                % fixed_parameters.p.as_ref()
    }

    pub fn combine(
        fixed_parameters: &FixedParameters,
        r: &[BigUint],
        com: &[Commitment],
    ) -> (BigUint, Commitment) {
        let res_r =
            r.iter().fold(BigUint::from(0u8), |acc, x| (acc + x)) % fixed_parameters.q.as_ref();

        let res_com = com.iter().fold(Commitment(BigUint::from(1u8)), |acc, x| {
            Commitment((&acc.0 * &x.0) % fixed_parameters.p.as_ref())
        });

        (res_r, res_com)
    }

    pub fn open(&self, fixed_parameters: &FixedParameters, h: &BigUint, r: &BigUint) -> BigUint {
        let p_minus_two = fixed_parameters.p.as_ref() - BigUint::from(2u8);
        let g_to_r_inverse = fixed_parameters
            .g
            .modpow(r, fixed_parameters.p.borrow())
            .modpow(&p_minus_two, fixed_parameters.p.borrow());

        let h_to_i = &self.0 * &g_to_r_inverse % fixed_parameters.p.as_ref();
        let dl = DiscreteLog::new(h, fixed_parameters.p.as_ref());
        dl.find(h, fixed_parameters.p.as_ref(), &h_to_i).unwrap()
    }
}

#[cfg(test)]
mod test {
    use crate::standard_parameters::STANDARD_PARAMETERS;

    use super::*;

    #[test]
    fn test_valid() {
        let mut csprng = Csprng::new(&[0u8]);
        let fixed_parameters = &STANDARD_PARAMETERS;
        let h = csprng.next_biguint_lt(fixed_parameters.q.borrow());

        for _ in 0..10 {
            let i = csprng.next_biguint_lt(fixed_parameters.q.borrow());
            let (r, com) = Commitment::new(&mut csprng, fixed_parameters, &h, &i);
            assert!(com.verify(fixed_parameters, &h, &i, &r));
        }
    }

    #[test]
    fn test_invalid() {
        let mut csprng = Csprng::new(&[0u8]);
        let fixed_parameters = &STANDARD_PARAMETERS;
        let h = csprng.next_biguint_lt(fixed_parameters.q.borrow());

        for _ in 0..10 {
            let i = csprng.next_biguint_lt(fixed_parameters.q.borrow());
            let j = csprng.next_biguint_lt(fixed_parameters.q.borrow());
            let (r, com) = Commitment::new(&mut csprng, fixed_parameters, &h, &i);
            assert!(!com.verify(fixed_parameters, &h, &j, &r));
        }
    }

    #[test]
    fn test_combine() {
        let mut csprng = Csprng::new(&[0u8]);
        let fixed_parameters = &STANDARD_PARAMETERS;
        let h = csprng.next_biguint_lt(fixed_parameters.q.borrow());

        let mut com_vec = Vec::new();
        let mut r_vec = Vec::new();
        let mut i_vec = Vec::new();

        for _ in 0..10 {
            let i = csprng.next_biguint_lt(fixed_parameters.q.borrow());
            let (r, com) = Commitment::new(&mut csprng, fixed_parameters, &h, &i);
            assert!(com.verify(fixed_parameters, &h, &i, &r));
            i_vec.push(i);
            r_vec.push(r);
            com_vec.push(com);
        }

        let i_sum = i_vec.iter().fold(BigUint::from(0u8), |acc, x| (acc + x));
        let (r_sum, com_sum) = Commitment::combine(fixed_parameters, &r_vec, &com_vec);
        assert!(com_sum.verify(fixed_parameters, &h, &i_sum, &r_sum));
    }

    #[test]
    fn test_open() {
        let mut csprng = Csprng::new(&[0u8]);
        let fixed_parameters = &STANDARD_PARAMETERS;
        let h = csprng.next_biguint_lt(fixed_parameters.q.borrow());
        for _ in 0..10 {
            let i = csprng.next_u32();
            let (r, com) = Commitment::new(&mut csprng, fixed_parameters, &h, &BigUint::from(i));
            let j = com.open(fixed_parameters, &h, &r);
            assert_eq!(BigUint::from(i), j);
        }
    }
}
