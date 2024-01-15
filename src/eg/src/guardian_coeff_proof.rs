#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides the implementation of the coefficient proof of knowledge for [`CoefficientCommitment`]s.
//! For more details see Section `3.2.2` of the Electionguard specification `2.0.0`.

use crate::{
    fixed_parameters::FixedParameters,
    guardian_secret_key::{CoefficientCommitment, SecretCoefficient},
    hash::{eg_h, HValue},
    hashes::ParameterBaseHash,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use util::{
    algebra::{FieldElement, GroupElement},
    csprng::Csprng,
};

/// Proof of possession for a single coefficient
///
/// This is a Sigma protocol for the dlog relation (also known as a Schnorr proof)
/// It corresponds to the tuple `(c_{i,j},v_{i,j})` in Section `3.2.2`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoefficientProof {
    /// Challenge
    pub challenge: HValue,
    /// Response
    pub response: FieldElement,
}

/// Represents errors occurring during the validation of a coefficient proof.
#[derive(Error, Debug)]
pub enum ProofValidationError {
    /// Occurs if the commitment is not a valid group element.
    #[error("The commitment is not a valid element in Z_p^r.")]
    CommitmentNotInGroup,
    /// Occurs if the response is not a valid field element.
    #[error("The proof response is not a valid element in Z_q.")]
    ResponseNotInField,
    /// Occurs if the computed challenge does not match the given one.
    #[error("The computed challenge does not match the given one.")]
    ChallengeMismatch,
}

impl CoefficientProof {
    /// This function computes the challenge for the coefficient NIZK as specified in Equation `12`.
    ///
    /// The arguments are
    /// - `fixed_parameters` - the fixed parameters
    /// - `i` - the guardian index
    /// - `j` - the coefficient index
    /// - `coefficient` - the coefficient commitment (`K_i_j` in the reference)
    /// - `h` - the commit message (`h_i_j` in the reference)
    fn challenge(
        fixed_parameters: &FixedParameters,
        i: u32,
        j: u32,
        coefficient: &GroupElement,
        h: &GroupElement,
    ) -> HValue {
        let h_p = ParameterBaseHash::compute(fixed_parameters).h_p;
        let group = &fixed_parameters.group;
        // v = 0x10 | b(i,4) | b(j,4) | b(coefficient,512) | b(h,512) for standard parameters
        let mut v = vec![0x10];
        v.extend_from_slice(i.to_be_bytes().as_slice());
        v.extend_from_slice(j.to_be_bytes().as_slice());
        v.extend_from_slice(coefficient.to_be_bytes_left_pad(&group).as_slice());
        v.extend_from_slice(h.to_be_bytes_left_pad(&group).as_slice());
        //The challenge is not reduced modulo q (cf. Section 5.4)
        eg_h(&h_p, &v)
    }

    /// This function computes a [`CoefficientProof`] from given [`SecretCoefficient`] and [`CoefficientCommitment`].
    ///
    /// The arguments are
    /// - `csprng` - secure randomness generator
    /// - `fixed_parameters` - the fixed parameters
    /// - `i` - the guardian index
    /// - `j` - the coefficient index
    /// - `coefficient` - the guardian's secret coefficient
    /// - `commitment` - the coefficient commitment
    pub fn new(
        csprng: &mut Csprng,
        fixed_parameters: &FixedParameters,
        i: u32,
        j: u32,
        coefficient: &SecretCoefficient,
        commitment: &CoefficientCommitment,
    ) -> Self {
        let coefficient = &coefficient.0;
        let commitment = &commitment.0;
        let field = &fixed_parameters.field;
        // Compute commit message
        let u = field.random_field_elem(csprng);
        let h = fixed_parameters.group.g_exp(&u);
        // Compute challenge
        let c = Self::challenge(fixed_parameters, i, j, commitment, &h);
        // Get field element from challenge, here the challenge is reduced mod `q`
        let c_val = FieldElement::from_bytes_be(c.0.as_slice(), &field);
        // Compute response
        let s = c_val.mul(coefficient, field);
        let v = u.sub(&s, field);
        CoefficientProof {
            challenge: c,
            response: v,
        }
    }

    /// This function verifies a [`CoefficientProof`] with respect to a given [`CoefficientCommitment`] and context.
    ///
    /// The arguments are
    /// - `self` - the `CoefficientProof`
    /// - `fixed_parameters` - the fixed parameters
    /// - `i` - the guardian index
    /// - `j` - the coefficient index
    /// - `commitment` - the coefficient commitment
    pub fn validate(
        &self,
        fixed_parameters: &FixedParameters,
        i: u32,
        j: u32,
        commitment: &CoefficientCommitment,
    ) -> Result<(), ProofValidationError> {
        let commitment = &commitment.0;

        let group = &fixed_parameters.group;
        let field = &fixed_parameters.field;

        // Verification check (2.A) 0 <= commitment < p and commitment^q = 1
        if !commitment.is_valid(group) {
            return Err(ProofValidationError::CommitmentNotInGroup);
        }
        // Verification check (2.B) 0 <= response < q
        if !self.response.is_valid(field) {
            return Err(ProofValidationError::ResponseNotInField);
        }
        // Equation (2.1)
        let c_val = FieldElement::from_bytes_be(self.challenge.0.as_slice(), &field);
        let h = group
            .g_exp(&self.response)
            .mul(&commitment.exp(&c_val, group), group);
        // Verification check (2.C)
        if self.challenge != Self::challenge(fixed_parameters, i, j, commitment, &h) {
            return Err(ProofValidationError::ChallengeMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use util::csprng::Csprng;

    use crate::{
        example_election_parameters::example_election_parameters,
        fixed_parameters::FixedParameters,
        guardian_secret_key::{CoefficientCommitment, SecretCoefficient},
    };

    use super::CoefficientProof;

    fn setup(
        csprng: &mut Csprng,
        fixed_parameters: &FixedParameters,
    ) -> (SecretCoefficient, CoefficientCommitment) {
        let coefficient = SecretCoefficient(fixed_parameters.field.random_field_elem(csprng));
        let commitment = CoefficientCommitment(fixed_parameters.group.g_exp(&coefficient.0));
        (coefficient, commitment)
    }

    #[test]
    fn test_guardian_proof_generation() {
        let mut csprng = Csprng::new(b"test_proof_generation");
        let fixed_parameters = example_election_parameters().fixed_parameters;
        let (coefficient, commitment) = setup(&mut csprng, &fixed_parameters);

        let i: u32 = 1;
        let j: u32 = 42;

        let proof = CoefficientProof::new(
            &mut csprng,
            &fixed_parameters,
            i,
            j,
            &coefficient,
            &commitment,
        );

        assert!(
            proof.validate(&fixed_parameters, i, j, &commitment).is_ok(),
            "Proof should be valid"
        );
    }

    #[test]
    fn test_guardian_proof_generation_wrong_index() {
        let mut csprng = Csprng::new(b"test_proof_generation");
        let fixed_parameters = example_election_parameters().fixed_parameters;
        let (coefficient, commitment) = setup(&mut csprng, &fixed_parameters);

        let i: u32 = 1;
        let i_prime: u32 = 2;
        let j: u32 = 42;
        let j_prime: u32 = 43;

        let proof = CoefficientProof::new(
            &mut csprng,
            &fixed_parameters,
            i,
            j,
            &coefficient,
            &commitment,
        );

        assert!(
            proof
                .validate(&fixed_parameters, i_prime, j, &commitment)
                .is_err(),
            "Proof should fail"
        );
        assert!(
            proof
                .validate(&fixed_parameters, i, j_prime, &commitment)
                .is_err(),
            "Proof should fail"
        );
    }
}
