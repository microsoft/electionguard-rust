use std::borrow::Borrow;

use crate::{
    election_parameters::ElectionParameters,
    guardian::GuardianIndex,
    guardian_public_key_info::GuardianPublicKeyInfo,
    guardian_secret_key::{CoefficientCommitments, GuardianSecretKey, SecretCoefficients},
    hash::{eg_h, HValue},
};
use anyhow::{ensure, Context, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoefficientProof {
    /// Challenge vector
    pub c: Vec<BigUint>,
    /// Response vector
    pub v: Vec<BigUint>,
}

impl CoefficientProof {
    /// This function computes the challenge for the coefficient NIZK as specified in Equation (12)
    /// The arguments are
    /// - h_p - the parameter base hash
    /// - i - the guardian index
    /// - j - the coefficient index
    /// - capital_k_i_j - the coefficient commitment
    /// - h_i_j - the commit message
    pub fn challenge(
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
        let c = eg_h(&h_p, &v);
        //The challenge is not reduced modulo q (cf. Section 5.4)
        BigUint::from_bytes_be(c.0.as_slice())
    }

    /// This function computes coefficient NIZK proof as specified in Section 3.2.2
    /// The arguments are
    /// - csprng - secure randomness generator
    /// - election_parameters - the election parameters
    /// - h_p - the parameter base hash
    /// - i - the guardian index
    /// - secret_coefficients - the coefficients
    /// - coefficient_commitments - the coefficients commitments
    pub fn new(
        csprng: &mut Csprng,
        election_parameters: &ElectionParameters,
        h_p: HValue,
        i: GuardianIndex,
        secret_coefficients: &SecretCoefficients,
        coefficient_commitments: &CoefficientCommitments,
    ) -> Self {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;
        let k = varying_parameters.k;
        let i = i.get_one_based_usize();

        // Compute commit message
        let u_vec = (0..k.get_one_based_u32())
            .map(|_j| csprng.next_biguint_lt(fixed_parameters.q.borrow()))
            .collect::<Vec<BigUint>>();
        let h_vec = u_vec
            .iter()
            .map(|u_i| fixed_parameters.g.modpow(u_i, fixed_parameters.p.as_ref()))
            .collect::<Vec<BigUint>>();
        // Compute challenge vector
        let c_vec = (0..k.get_one_based_usize())
            .map(|j| Self::challenge(h_p, i, j, &coefficient_commitments.0[j].0, &h_vec[j]))
            .collect::<Vec<BigUint>>();
        // Compute response vector
        let v_vec = (0..k.get_one_based_usize())
            .map(|j| {
                fixed_parameters
                    .q
                    .subtract_group_elem(&u_vec[j], &(&c_vec[j] * &secret_coefficients.0[j].0))
            })
            .collect::<Vec<BigUint>>();
        CoefficientProof { c: c_vec, v: v_vec }
    }

    /// This function verifies a coefficient NIZK proof with respect to given commitments and parameters
    /// This is corresponds to Verification 2 "Guardian public-key validation"
    /// The arguments are
    /// - self - the NIZK proof
    /// - election_parameters - the election parameters
    /// - h_p - the parameter base hash
    /// - i - the guardian index
    /// - coefficient_commitments - the coefficients commitments
    pub fn verify(
        &self,
        election_parameters: &ElectionParameters,
        h_p: HValue,
        i: GuardianIndex,
        coefficient_commitments: &CoefficientCommitments,
    ) -> bool {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;
        let k = varying_parameters.k;
        let i = i.get_one_based_usize();
        // Equation (2.1)
        let h_vec = (0..k.get_one_based_usize())
            .map(|j| {
                fixed_parameters
                    .g
                    .modpow(&self.v[j], fixed_parameters.p.borrow())
                    * coefficient_commitments.0[j]
                        .0
                        .modpow(&self.c[j], fixed_parameters.p.borrow())
                    % fixed_parameters.p.as_ref()
            })
            .collect::<Vec<BigUint>>();
        // Verification 2 checks
        let zero = BigUint::from(0u8);
        let one = BigUint::from(1u8);
        let mut verified = true;
        for j in 0..k.get_one_based_usize() {
            let capital_k_i_j = &coefficient_commitments.0[j].0;
            // 2.A
            verified &= (zero <= *capital_k_i_j) && (*capital_k_i_j < *fixed_parameters.p.borrow());
            verified &= capital_k_i_j
                .modpow(fixed_parameters.q.borrow(), fixed_parameters.p.borrow())
                == one;
            // 2.B
            verified &= (zero <= self.v[j]) && (self.v[j] < *fixed_parameters.q.borrow());
            // 2.C
            verified &= self.c[j] == Self::challenge(h_p, i, j, capital_k_i_j, &h_vec[j])
        }
        verified
    }
}

/// Proof of Possession for the coefficient in a guardian's secret key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianProof {
    /// Guardian number, 1 <= i <= [`crate::varying_parameters::VaryingParameters::n`].
    pub i: GuardianIndex,

    /// NiZK for polynomial coefficients
    pub coefficient_proof: CoefficientProof,
}

impl GuardianProof {
    /// Generates a `GuardianProof` given the election parameter and a secret key
    pub fn generate(
        csprng: &mut Csprng,
        election_parameters: &ElectionParameters,
        h_p: HValue,
        secret_key: &GuardianSecretKey,
    ) -> Self {
        let i = secret_key.i;
        let coefficient_proof = CoefficientProof::new(
            csprng,
            election_parameters,
            h_p,
            i,
            &secret_key.secret_coefficients,
            &secret_key.coefficient_commitments,
        );
        assert!(coefficient_proof.verify(
            election_parameters,
            h_p,
            i,
            &secret_key.coefficient_commitments
        ));
        GuardianProof {
            i,
            coefficient_proof,
        }
    }

    /// Validates a `GuardianProof` given the election parameter and a `GuardianPublicKeyInfo`
    pub fn validate(
        &self,
        election_parameters: &ElectionParameters,
        h_p: HValue,
        public_key_info: &dyn GuardianPublicKeyInfo,
    ) -> Result<()> {
        ensure!(
            self.i == public_key_info.i(),
            "The guardian indices of the proof and the public key must match."
        );

        ensure!(
            self.coefficient_proof.verify(
                election_parameters,
                h_p,
                self.i,
                public_key_info.coefficient_commitments()
            ),
            "The proof is invalid."
        );

        Ok(())
    }

    /// Reads a `GuardianProof` from a `std::io::Read`. Validation will require the corresponding public key.
    pub fn from_stdioread_validated(stdioread: &mut dyn std::io::Read) -> Result<Self> {
        let self_: Self = serde_json::from_reader(stdioread).context("Reading GuardianProof")?;
        Ok(self_)
    }

    /// Writes a `GuardianProof` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing GuardianProof")
    }
}

#[cfg(test)]
mod test {
    use std::iter::zip;
    use util::csprng::Csprng;

    use crate::{
        example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters, hashes::Hashes, guardian::GuardianIndex,
    };

    use super::{GuardianProof, GuardianSecretKey};

    #[test]
    fn test_guardian_proof_generation() {
        let mut csprng = Csprng::new(b"test_proof_generation");

        let election_parameters = example_election_parameters();
        let election_manifest = example_election_manifest();
        let varying_parameters = &election_parameters.varying_parameters;

        let hashes = Hashes::compute(&election_parameters, &election_manifest).unwrap();

        let guardian_secret_keys = varying_parameters
            .each_guardian_i()
            .map(|i| GuardianSecretKey::generate(&mut csprng, &election_parameters, i, None))
            .collect::<Vec<_>>();

        let guardian_public_keys = guardian_secret_keys
            .iter()
            .map(|secret_key| secret_key.make_public_key())
            .collect::<Vec<_>>();

        let guardian_proofs = guardian_secret_keys
            .iter()
            .map(|secret_key| {
                GuardianProof::generate(&mut csprng, &election_parameters, hashes.h_p, secret_key)
            })
            .collect::<Vec<_>>();

        for (pk, proof) in zip(guardian_public_keys, guardian_proofs) {
            let proof_index = proof.i;
            let pk_index = pk.i;
            assert!(
                proof
                    .validate(&election_parameters, hashes.h_p, &pk)
                    .is_ok(),
                "Proof {proof_index} for key {pk_index} is invalid."
            )
        }

    }

    #[test]
    fn test_guardian_proof_generation_wrong_index() {
        let mut csprng = Csprng::new(b"test_proof_generation");

        let election_parameters = example_election_parameters();
        let election_manifest = example_election_manifest();
        let varying_parameters = &election_parameters.varying_parameters;

        let hashes = Hashes::compute(&election_parameters, &election_manifest).unwrap();

        let index_one = GuardianIndex::from_one_based_index(1).unwrap();
        let index_two = GuardianIndex::from_one_based_index(2).unwrap();
        let sk_one = GuardianSecretKey::generate(&mut csprng, &election_parameters, index_one, None);        
        let sk_two = GuardianSecretKey::generate(&mut csprng, &election_parameters, index_two, None);     

        let proof = GuardianProof::generate(&mut csprng, &election_parameters, hashes.h_p, &sk_one);

        assert!(proof.validate(&election_parameters, hashes.h_p, &sk_two.make_public_key()).is_err(), "Proof validation should fail")

    }
}
