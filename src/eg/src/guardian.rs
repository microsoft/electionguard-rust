use std::fs;
use std::{borrow::Borrow, path::PathBuf, rc::Rc};

use num_bigint::BigUint;
use num_traits::Num;

use util::{
    csprng::Csprng,
    z_mul_prime::{ZMulPrime, ZMulPrimeElem},
};

use crate::{
    election_parameters::ElectionParameters, fixed_parameters::FixedParameters, hash::HValue,
    key::PublicKey, nizk::ProofGuardian,
};
pub struct Guardian {
    poly: Polynomial,
    commitment: Vec<BigUint>,
}
struct Polynomial {
    a: Vec<ZMulPrimeElem>,
}

/// Aggregates public keys from guardians
pub fn aggregate_public_keys(
    fixed_parameters: &FixedParameters,
    capital_k_i: &[PublicKey],
) -> BigUint {
    let mut capital_k = BigUint::from(1 as u8);
    for capital_k_i_j in capital_k_i {
        capital_k = (&capital_k * &capital_k_i_j.0) % fixed_parameters.p.as_ref();
    }
    capital_k
}

pub fn export(dir: &PathBuf, public_key: &PublicKey, proof: &ProofGuardian, shares: &Vec<String>) {
    let private_dir = dir.join("private");
    let public_dir = dir.join("public");
    fs::create_dir_all(private_dir.clone()).unwrap();
    fs::create_dir_all(public_dir.clone()).unwrap();

    fs::write(
        public_dir.join("public_key.json"),
        serde_json::to_string(public_key).unwrap(),
    )
    .unwrap();
    fs::write(
        public_dir.join("proof.json"),
        serde_json::to_string(proof).unwrap(),
    )
    .unwrap();
    fs::write(
        private_dir.join("shares.json"),
        serde_json::to_string(shares).unwrap(),
    )
    .unwrap();
}

pub fn verify_share_from(
    fixed_parameters: &FixedParameters,
    l: usize,
    p_i_of_l: &BigUint,
    capital_k_i: &[BigUint],
) -> bool {
    let lhs = fixed_parameters
        .g
        .modpow(p_i_of_l, fixed_parameters.p.borrow());

    let mut rhs = BigUint::from(1 as u8);
    let l = BigUint::from(l as usize);
    for j in 0..capital_k_i.len() {
        rhs = (rhs * capital_k_i[j].modpow(&l.pow(j as u32), fixed_parameters.p.borrow()))
            % fixed_parameters.p.as_ref();
    }

    lhs == rhs
}

pub fn import(dir: &PathBuf, i: usize) -> (PublicKey, ProofGuardian, BigUint) {
    let private_dir = dir.join("private");
    let public_dir = dir.join("public");

    let public_key: PublicKey =
        serde_json::from_str(&fs::read_to_string(public_dir.join("public_key.json")).unwrap())
            .unwrap();
    let proof: ProofGuardian =
        serde_json::from_str(&fs::read_to_string(public_dir.join("proof.json")).unwrap()).unwrap();
    let shares: Vec<String> =
        serde_json::from_str(&fs::read_to_string(private_dir.join("shares.json")).unwrap())
            .unwrap();
    (
        public_key,
        proof,
        BigUint::from_str_radix(&shares[i - 1], 16).unwrap(),
    )
}

impl Polynomial {
    pub fn new(csprng: &mut Csprng, zmulp: Rc<ZMulPrime>, degree: usize) -> Self {
        let a = (0..degree + 1)
            .map(|_| ZMulPrimeElem::new_pick_random(zmulp.clone(), csprng))
            .collect::<Vec<ZMulPrimeElem>>();
        Polynomial { a }
    }

    pub fn evaluate(&self, x: &BigUint) -> BigUint {
        let mut y = BigUint::from(0 as u8);
        match ZMulPrimeElem::try_new(self.a[0].zmulp.clone(), x.clone()) {
            Some(x) => {
                for (j, a_j) in self.a.iter().enumerate() {
                    y += (&a_j.elem
                        * x.elem
                            .modpow(&BigUint::from(j as usize), a_j.zmulp.p.borrow()))
                        % a_j.zmulp.p.as_ref();
                }
            }
            None => {}
        };
        y
    }

    pub fn commit(&self, fixed_parameters: &FixedParameters) -> Vec<BigUint> {
        let mut capital_k = Vec::new();
        for j in 0..self.a.len() {
            capital_k.push(
                fixed_parameters
                    .g
                    .modpow(&self.a[j].elem, fixed_parameters.p.borrow()),
            );
        }
        capital_k
    }
}

impl Guardian {
    pub fn new(csprng: &mut Csprng, election_parameters: &ElectionParameters) -> Self {
        let zmulq = Rc::new(ZMulPrime::new(
            election_parameters.fixed_parameters.q.clone(),
        ));
        let poly = Polynomial::new(
            csprng,
            zmulq,
            election_parameters.varying_parameters.k as usize,
        );
        let commitment = poly.commit(&election_parameters.fixed_parameters);
        Guardian { poly, commitment }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.commitment[0].clone())
    }

    pub fn share_for(&self, l: usize) -> String {
        self.poly.evaluate(&BigUint::from(l)).to_str_radix(16)
    }

    pub fn proof_of_knowledge(
        &self,
        csprng: &mut Csprng,
        election_parameters: &ElectionParameters,
        h_p: HValue,
        i: u16,
    ) -> ProofGuardian {
        let zmulq = Rc::new(ZMulPrime::new(
            election_parameters.fixed_parameters.q.clone(),
        ));
        ProofGuardian::new(
            csprng,
            &election_parameters.fixed_parameters,
            h_p,
            zmulq,
            i,
            election_parameters.varying_parameters.k,
            self.commitment.as_slice(),
            self.poly
                .a
                .iter()
                .map(|x| x.elem.clone())
                .collect::<Vec<BigUint>>()
                .as_slice(),
        )
    }

    pub fn verify_proof_of_knowledge() -> bool {
        unimplemented!()
    }
}
