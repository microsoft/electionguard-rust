#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides the implementation of the coefficient proof of knowledge for [`CoefficientCommitment`]s.
//! For more details see Section `3.2.2` of the Electionguard specification `2.1.0`. [TODO check ref]

use std::{iter::OnceWith, sync::Arc};

use serde::{Deserialize, Serialize};
use util::{
    algebra::{FieldElement, GroupElement, ScalarField},
    csrng::Csrng,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    eg::Eg,
    el_gamal::{ElGamalPublicKey, ElGamalSecretKey},
    election_parameters::ElectionParameters,
    errors::{EgError, EgResult},
    guardian::{GuardianIndex, GuardianKeyPartId, GuardianKeyPurpose},
    guardian_public_key_trait::GuardianKeyInfoTrait,
    guardian_secret_key::{
        CoefficientCommitment, CoefficientCommitments, GuardianSecretKey, SecretCoefficient,
        SecretCoefficients,
    },
    hash::{HVALUE_BYTE_LEN, eg_h, eg_h_q_as_field_element},
    hashes::ParameterBaseHash,
    resource::{ProduceResource, ProduceResourceExt},
};

/// Represents errors occurring during the validation of a coefficient proof.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
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

/// Proof of knowledge of a specific [`GuardianSecretKey`], and
/// commitment to a specific public communication key.
///
/// EGDS 2.1.0 bottom of pg. 23:
/// "publishes the proof
/// (c_i, v_{i,0}, v_{i,1}, ..., v_{i,k-1}, v_{i,k}) consisting of
/// the challenge value c_i and
/// the response values v_{i,j} = (u_{i,j} − c_i*a_{i,j}) mod q (0 ≤ j < k) and
/// v_{i,k} = (u_{i,k} − c_i*ζ_i) mod q together with
/// (K_{i,0}, K_{i,1}, ..., K_{i,k-1}) and κ_i."
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CoefficientsProof {
    guardian_key_id: GuardianKeyPartId,

    /// EGDS 2.1.0 eq. 11 pg. 23
    c_i: FieldElement,

    /// EGDS 2.1.0 bottom of pg. 23 "response values"
    vec_v_i_j: Vec<FieldElement>,

    /// EGDS 2.1.0 bottom of pg. 21 "K_{i,j}"
    coefficient_commitments: Arc<CoefficientCommitments>,

    /// EGDS 2.1.0 eq. 9 pg. 23
    guardian_commms_public_key: Arc<ElGamalPublicKey>,
}

impl CoefficientsProof {
    /// The [`GuardianKeyId`] to which this proof applies.
    #[allow(dead_code)]
    fn guardian_key_id(&self) -> &GuardianKeyPartId {
        &self.guardian_key_id
    }

    /// EGDS 2.1.0 sec 3.3.2 pg 23 eq. 10-11.
    ///
    /// - `eg` - [`Eg`] context
    /// - `guardian_secret_key` - the [`GuardianSecretKey`] for which the NIZK proof is being generated.
    /// - `guardian_comms_secret_key` - the [`ElGamalSecretKey`] for this guardian.
    #[allow(dead_code)] //? TODO: Remove temp development code
    pub(crate) async fn generate(
        produce_resource: &(dyn crate::resource::ProduceResource + Send + Sync + 'static),
        guardian_secret_key: &GuardianSecretKey,
        guardian_comms_secret_key: &ElGamalSecretKey,
    ) -> EgResult<CoefficientsProof> {
        let guardian_key_id = *guardian_secret_key.guardian_key_id();

        let election_parameters = produce_resource.election_parameters().await?;

        let fixed_parameters = election_parameters.fixed_parameters();
        let field = fixed_parameters.field();
        let group = fixed_parameters.group();

        let varying_parameters = election_parameters.varying_parameters();
        let k = varying_parameters.k().as_quantity();

        let csrng = produce_resource.csrng();
        let q_len_bytes = field.q_len_bytes();
        let p_len_bytes = group.p_len_bytes();

        let secret_coefficients = guardian_secret_key.secret_coefficients();
        debug_assert_eq!(guardian_secret_key.secret_coefficients().len(), k);

        let aby_pk_label = match guardian_key_id.key_purpose {
            GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields => b"pk_vote",
            GuardianKeyPurpose::Encrypt_Ballot_AdditionalFreeFormData => b"pk_data",
            _ => Err(EgError::NoJointPublicKeyForPurpose {
                key_purpose: guardian_key_id.key_purpose,
            })?,
        };

        // EGDS 2.1.0 sec 3.3.2 pg 23:
        // "For each 0 ≤ j ≤ k, Guardian G_i generates a random integer value u_{i,j} in Z_q"
        //? TODO zeroize on drop
        let vec_u_i_j =
            Vec::from_iter(std::iter::repeat_with(|| field.random_field_elem(csrng)).take(k + 1));
        debug_assert_eq!(vec_u_i_j.len(), k + 1);

        // EGDS 2.1.0 sec 3.3.2 eq. 10:
        // "h_{i,j} = g^{u_{i,j}} mod p"
        //? TODO zeroize on drop
        let vec_h_i_j: Vec<GroupElement> =
            vec_u_i_j.iter().map(|u_i_j| group.g_exp(u_i_j)).collect();
        debug_assert_eq!(vec_h_i_j.len(), k + 1);

        let guardian_commms_public_key = guardian_comms_secret_key.public_key(group)?;
        let kappa_i = guardian_commms_public_key.kappa();

        // Buffer for computing EGDS 2.1.0 eq. 11
        let expected_len = 1
            + aby_pk_label.len()
            + 4 // guardian ix
            + q_len_bytes*k // K_{i,0≤j<k}
            + p_len_bytes // kappa_i
            + p_len_bytes*(k + 1); // h_{i,j} where 0 <= j <= k

        let mut vec_msg_bytes: Vec<u8> = Vec::with_capacity(expected_len);
        vec_msg_bytes.push(0x10);
        vec_msg_bytes.extend(aby_pk_label);
        vec_msg_bytes.extend(guardian_key_id.guardian_ix.get_one_based_4_be_bytes());

        for capitalk_i_j in secret_coefficients.iter() {
            vec_msg_bytes
                .extend_from_slice(capitalk_i_j.as_ref().to_be_bytes_left_pad(field).as_slice());
        }

        vec_msg_bytes.extend_from_slice(kappa_i.to_be_bytes_left_pad(group).as_slice());

        for h_i_j in vec_h_i_j.iter() {
            vec_msg_bytes.extend_from_slice(h_i_j.to_be_bytes_left_pad(group).as_slice());
        }

        assert_eq!(vec_msg_bytes.len(), expected_len);

        let expected_len = 12 + (k + 1) * 2 * 512; // EGDS 2.1.0 pg. 74 (11, 13)
        assert_eq!(vec_msg_bytes.len(), expected_len);

        let hashes = produce_resource.hashes().await?;
        let h_p = hashes.h_p();
        let c_i = eg_h_q_as_field_element(h_p, &vec_msg_bytes, field);

        let zeta_i = guardian_comms_secret_key.zeta();

        // Pair `k + 1` of the u_{i,j} with the `k` of `capitalk_i_j` and zeta_i field elements.
        let u_a_pair_i_j = std::iter::zip(
            vec_u_i_j.iter(),
            secret_coefficients
                .iter()
                .map(AsRef::<FieldElement>::as_ref)
                .chain(std::iter::once(zeta_i)),
        );

        let vec_v_i_j: Vec<FieldElement> = u_a_pair_i_j
            .map(|(u_i_j, a_i_j)| u_i_j.sub(&c_i.mul(a_i_j, field), field))
            .collect();

        let coefficient_commitments =
            Arc::new(guardian_secret_key.coefficient_commitments().clone());

        let coefficients_proof = CoefficientsProof {
            guardian_key_id,
            c_i,
            vec_v_i_j,
            coefficient_commitments,
            guardian_commms_public_key,
        };

        Ok(coefficients_proof)
    }
}

/*
/// Proof of possession for a single coefficient
///
/// This is a Sigma protocol for the dlog relation (also known as a Schnorr proof)
/// It corresponds to the tuple `(c_{i,j},v_{i,j})` in Section `3.2.2`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoefficientProof {
}

impl CoefficientProof {
    /// EGDS 2.1.0 sec 3.3.2 pg 23 eq. 11 NIZK proof challenge value `c_i`.
    ///
    /// The arguments are
    /// - `election_parameters` - The [`ElectionParameters`]
    /// - `guardian_ix` - [guardian index](GuardianIndex)
    /// - `coefficient` - the coefficient commitment (`K_i_j` in the reference)
    /// - `h` - the commit message (`h_i_j` in the reference)
    fn challenge(
        election_parameters: &ElectionParameters,
        guardian_ix: GuardianIndex,
        j: u32,
        coefficient: &GroupElement,
        h: &GroupElement,
    ) -> FieldElement {
        let h_p = ParameterBaseHash::compute(election_parameters).h_p;
        let fixed_parameters = election_parameters.fixed_parameters();
        let group = fixed_parameters.group();

        // v = 0x10 | b(i, 4) | b(j, 4) | b(coefficient, 512) | b(h, 512) for standard parameters
        let mut v = vec![0x10];
        v.extend(guardian_ix.get_one_based_4_be_bytes());
        v.extend_from_slice(u32::to_be_bytes(j).as_slice());
        v.extend_from_slice(coefficient.to_be_bytes_left_pad(group).as_slice());
        v.extend_from_slice(h.to_be_bytes_left_pad(group).as_slice());
        let c_bytes = eg_h(&h_p, &v);

        // Get field element from challenge, here the challenge is reduced mod `q`
        FieldElement::from_bytes_be(c_bytes.0.as_slice(), &fixed_parameters.field)
    }

    /// Computes a [`CoefficientProof`] from given [`SecretCoefficient`] and [`CoefficientCommitment`].
    ///
    /// The arguments are
    /// - `csrng` - secure randomness generator
    /// - `election_parameters` - the election parameters
    /// - `guardian_ix` - the guardian index
    /// - `j` - the coefficient index
    /// - `coefficient` - the guardian's secret coefficient
    /// - `commitment` - the coefficient commitment
    pub fn new(
        csrng: &dyn Csrng,
        election_parameters: &ElectionParameters,
        guardian_ix: GuardianIndex,
        j: u32,
        coefficient: &SecretCoefficient,
        commitment: &CoefficientCommitment,
    ) -> Self {
        let fixed_parameters = election_parameters.fixed_parameters();
        let coefficient = &coefficient.0;
        let commitment = &commitment.0;
        let field = fixed_parameters.field();

        // Compute commit message
        let u = field.random_field_elem(csrng);
        let h = fixed_parameters.group.g_exp(&u);

        // Compute challenge
        let c = Self::challenge(election_parameters, guardian_ix, j, commitment, &h);

        // Compute response
        let s = c.mul(coefficient, field);
        let v = u.sub(&s, field);

        CoefficientProof {
            challenge: c,
            response: v,
        }
    }

    /// Verifies a [`CoefficientProof`] with respect to a given [`CoefficientCommitment`] and context.
    ///
    /// The arguments are
    /// - `self` - the `CoefficientProof`
    /// - `election_parameters` - the election parameters
    /// - `guardian_ix` - the guardian index
    /// - `j` - the coefficient index
    /// - `commitment` - the coefficient commitment
    pub fn validate(
        &self,
        election_parameters: &ElectionParameters,
        guardian_ix: GuardianIndex,
        j: u32,
        commitment: &CoefficientCommitment,
    ) -> Result<(), ProofValidationError> {
        let commitment = &commitment.0;

        let fixed_parameters = election_parameters.fixed_parameters();
        let group = fixed_parameters.group();
        let field = fixed_parameters.field();

        // Verification check (2.A) 0 <= commitment < p and commitment^q = 1 [TODO fix ref]
        if !commitment.is_valid(group) {
            return Err(ProofValidationError::CommitmentNotInGroup);
        }

        // Verification check (2.B) 0 <= response < q [TODO fix ref]
        if !self.response.is_valid(field) {
            return Err(ProofValidationError::ResponseNotInField);
        }

        // Equation (2.1) [TODO fix ref]
        let h = group
            .g_exp(&self.response)
            .mul(&commitment.exp(&self.challenge, group), group);

        // Verification check (2.C)
        if self.challenge != Self::challenge(election_parameters, guardian_ix, j, commitment, &h) {
            return Err(ProofValidationError::ChallengeMismatch);
        }

        Ok(())
    }
}
// */

#[cfg(test)]
#[allow(clippy::unwrap_used)] // This is unit test code
mod t0 {
    use util::csrng::Csrng;

    use super::CoefficientsProof;
    use crate::{
        eg::Eg,
        errors::EgResult,
        fixed_parameters::FixedParameters,
        guardian::GuardianIndex,
        guardian_secret_key::{CoefficientCommitment, SecretCoefficient},
    };
    /*

    fn set_up(
        csrng: &dyn Csrng,
        fixed_parameters: &FixedParameters,
    ) -> (SecretCoefficient, CoefficientCommitment) {
        let coefficient = SecretCoefficient(fixed_parameters.field.random_field_elem(csrng));
        let commitment = CoefficientCommitment(fixed_parameters.group.g_exp(&coefficient.0));
        (coefficient, commitment)
    }
    #[test_log::test]
    fn test_guardian_proof_generation() -> EgResult<()> {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::guardian_coeff_proof::t0::test_guardian_proof_generation");
        let eg = eg.as_ref();
        let pre_voting_data = produce_resource.pre_voting_data().await?;
        let pre_voting_data = pre_voting_data.as_ref();
        let election_parameters = pre_voting_data.election_parameters();
        let fixed_parameters = election_parameters.fixed_parameters();
        let csrng = eg.csrng();

        let (coefficient, commitment) = set_up(csrng, fixed_parameters);

        let i_guardian_ix = GuardianIndex::one();
        let j: u32 = 42;

        let proof = CoefficientProof::new(
            csrng,
            election_parameters,
            i_guardian_ix,
            j,
            &coefficient,
            &commitment,
        );

        assert!(
            proof
                .validate(election_parameters, i_guardian_ix, j, &commitment)
                .is_ok(),
            "Proof should be valid"
        );
        Ok(())
    }

    #[test_log::test]
    fn test_guardian_proof_generation_wrong_index() -> EgResult<()> {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::guardian_coeff_proof::t0::test_guardian_proof_generation_wrong_index");
        let pre_voting_data = produce_resource.pre_voting_data().await?;
        let eg = eg.as_ref();

        let pre_voting_data = pre_voting_data.as_ref();
        let election_parameters = pre_voting_data.election_parameters();
        let fixed_parameters = election_parameters.fixed_parameters();
        let csrng = eg.csrng();

        let (coefficient, commitment) = set_up(csrng, fixed_parameters);

        let i_guardian_ix = GuardianIndex::one();
        let i_guardian_ix_prime = GuardianIndex::try_from_one_based_index(2).unwrap();

        let j: u32 = 42;
        let j_prime: u32 = 43;

        let proof = CoefficientProof::new(
            csrng,
            election_parameters,
            i_guardian_ix,
            j,
            &coefficient,
            &commitment,
        );

        assert!(
            proof
                .validate(election_parameters, i_guardian_ix_prime, j, &commitment)
                .is_err(),
            "Proof should fail"
        );
        assert!(
            proof
                .validate(election_parameters, i_guardian_ix, j_prime, &commitment)
                .is_err(),
            "Proof should fail"
        );
        Ok(())
    }
    // */
}
