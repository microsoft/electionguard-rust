// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use util::vec1::Vec1;
use util::{algebra::FieldElement, csrng::Csrng};

/// Same type as [`CiphertextIndex`](crate::ciphertext::CiphertextIndex), [`ContestOptionIndex`](crate::election_manifest::ContestOptionIndex), [`ContestOptionFieldPlaintextIndex`](crate::contest_option_fields::ContestOptionFieldPlaintextIndex), [`ContestDataFieldIndex`](crate::contest_data_fields_plaintexts::ContestDataFieldIndex), etc.
pub use crate::contest_data_fields_plaintexts::ContestDataFieldIndex;
use crate::{
    ballot::BallotNonce_xi_B,
    ballot::HValue_H_I,
    ballot_scaled::ContestEncryptedScaled,
    ciphertext::Ciphertext,
    contest_data_fields_plaintexts::{ContestDataFieldPlaintext, ContestDataFieldsPlaintexts},
    contest_hash::contest_hash_chi_l,
    eg::Eg,
    election_manifest::ContestIndex,
    errors::{EgError, EgResult},
    fixed_parameters::FixedParameters,
    hash::HValue,
    nonce::{NonceFE, derive_xi_i_j_as_hvalue},
    pre_voting_data::PreVotingData,
    resource::{ProduceResource, ProduceResourceExt},
    selection_limits::EffectiveContestSelectionLimit,
    zk::ProofRange,
};

//-------------------------------------------------------------------------------------------------|

/// A contest in an encrypted ballot.
///
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContestDataFieldsCiphertexts {
    /// 1-based index of the contest within the [`ElectionManifest`].
    contest_ix: ContestIndex,

    /// [`Ciphertext`]s produced by encrypting contest data fields, which can be selectable
    /// options or additional data.
    pub ciphertexts: Vec1<Ciphertext>,

    //? TODO Preencrypted ballots
    // /// Encrypted voter selection vector.
    // pub selection: Vec<Ciphertext>,
    /// Contest hash.
    pub contest_hash: HValue,

    /// Proof of ballot correctness.
    pub proof_ballot_correctness: Vec1<ProofRange>,

    // Proof of satisfying the selection limit.
    pub proof_selection_limit: ProofRange,
}

impl ContestDataFieldsCiphertexts {
    /// Attempts to create a [`ContestDataFieldsCiphertexts`] by encrypting a [`ContestDataFieldsPlaintexts`].
    /// Also constructs the proof of ballot correctness.
    #[allow(non_snake_case)]
    pub async fn from_contest_data_fields_plaintexts(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        h_i: &HValue_H_I,
        ballot_nonce_xi_B: &BallotNonce_xi_B,
        contest_ix: ContestIndex,
        data_fields_plaintexts: ContestDataFieldsPlaintexts,
    ) -> EgResult<ContestDataFieldsCiphertexts> {
        let pre_voting_data = produce_resource.pre_voting_data().await?;
        let pre_voting_data = pre_voting_data.as_ref();
        let election_parameters = pre_voting_data.election_parameters();
        let fixed_parameters = election_parameters.fixed_parameters();

        let contest = pre_voting_data
            .election_manifest()
            .get_contest_without_checking_ballot_style(contest_ix)?;

        let contest_data_fields_ciphertexts_and_nonces =
            Self::encrypt_contest_data_fields_plaintexts(
                produce_resource,
                fixed_parameters,
                h_i,
                ballot_nonce_xi_B,
                contest_ix,
                &data_fields_plaintexts,
            )
            .await?;
        debug_assert_eq!(
            contest_data_fields_ciphertexts_and_nonces.len(),
            data_fields_plaintexts.len()
        );

        let contest_options_effective_selection_limits =
            contest.figure_options_effective_selection_limits()?;

        let ciphertexts = Vec1::<Ciphertext>::try_from_iter(
            contest_data_fields_ciphertexts_and_nonces
                .iter()
                .cloned()
                .map(|(ct, _)| ct),
        )
        .map_err(Into::<EgError>::into)?;

        //? TODO
        let encrypted_contest_data_blocks: [HValue; 0] = [];

        let contest_hash = contest_hash_chi_l(
            pre_voting_data,
            h_i,
            contest_ix,
            ciphertexts.as_slice(),
            encrypted_contest_data_blocks.as_slice(),
        );

        let proof_ballot_correctness = {
            let mut v_range_proofs = Vec::with_capacity(contest.contest_options.len());
            'each_contest_data_field: for (
                contest_data_field_ix_0based,
                (contest_data_field_ciphertext, contest_data_field_nonce),
            ) in contest_data_fields_ciphertexts_and_nonces
                .iter()
                .enumerate()
            {
                // Unwrap() is justified here because we are iterating over collection ultimately derived from a Vec1.
                #[allow(clippy::unwrap_used)]
                let contest_data_field_ix =
                    ContestDataFieldIndex::try_from_zero_based_index(contest_data_field_ix_0based)
                        .unwrap();

                let data_field_plaintext: ContestDataFieldPlaintext = data_fields_plaintexts
                    .get(contest_data_field_ix)
                    .ok_or_else(|| {
                        EgError::ContestOptionIxOutOfRange(
                            contest_data_field_ix.get_one_based_u32(),
                        )
                    })?;

                // Only data fields that are contest options get range proofs.
                let Some(&effective_option_selection_limit) =
                    contest_options_effective_selection_limits.get(contest_data_field_ix)
                else {
                    break 'each_contest_data_field;
                };

                let data_field_range_proof = ProofRange::new(
                    pre_voting_data,
                    produce_resource.csrng(),
                    contest_data_field_ciphertext,
                    contest_data_field_nonce,
                    data_field_plaintext.into(),
                    effective_option_selection_limit.into(),
                )?;

                v_range_proofs.push(data_field_range_proof);
            }

            Vec1::try_from(v_range_proofs)?
        };

        // We should have generated a proof for each contest option.
        if proof_ballot_correctness.len() != contest.contest_options.len() {
            Err(anyhow!(
                "Mismatch between number of contest options and number of range proofs."
            ))?;
        }

        // Figure the sum of the values of the option fields.
        let mut option_fields_value_total: u64 = 0;
        for option_field_ix in contest.contest_options.indices() {
            let option_field_plaintext =
                data_fields_plaintexts.get(option_field_ix).ok_or_else(|| {
                    EgError::ContestOptionIxOutOfRange(option_field_ix.get_one_based_u32())
                })?;

            let option_field_pt_u64 = u64::from(option_field_plaintext);
            option_fields_value_total = option_fields_value_total
                .checked_add(option_field_pt_u64)
                .ok_or_else(|| EgError::OverflowInOptionFieldTotal {
                    contest_ix: contest_ix.get_one_based_u32(),
                    option_field_ix: option_field_ix.get_one_based_u32(),
                })?;
        }

        let proof_selection_limit = Self::proof_selection_limit(
            pre_voting_data,
            produce_resource.csrng(),
            contest_data_fields_ciphertexts_and_nonces.as_slice(),
            option_fields_value_total.try_into()?,
            contest.selection_limit.into(),
        )?;

        Ok(ContestDataFieldsCiphertexts {
            contest_ix,
            ciphertexts,
            contest_hash,
            proof_ballot_correctness,
            proof_selection_limit,
        })
    }

    /* /// Generate a range proof that the data field is in the range [0, 1].
    fn generate_range_proof_for_contest_data_field(
        &self,
        pre_voting_data: &PreVotingData,
        csrng: &Csprng,
        ciphertext: bool,
        xi_i_j: &ContestDataFieldEncryptionNonce_xi_i_j,
    ) -> Result<ProofRange, ZkProofRangeError> {
        ProofRange::new(
            pre_voting_data,
            eg.csrng(),
            self,
            xi_i_j.as_ref(),
            ciphertext.into(),
            1)
    } */

    /// Encrypts a [`ContestDataFieldsPlaintexts`] to the joint_vote_encryption_public_key_k
    /// and returns the resulting ciphertexts and nonces.
    #[allow(non_snake_case)]
    async fn encrypt_contest_data_fields_plaintexts(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        fixed_parameters: &FixedParameters,
        h_i: &HValue_H_I,
        ballot_nonce_xi_B: &BallotNonce_xi_B,
        contest_i: ContestIndex,
        data_fields_plaintexts: &ContestDataFieldsPlaintexts,
    ) -> EgResult<Vec<(Ciphertext, NonceFE)>> {
        let field = fixed_parameters.field();

        let joint_vote_encryption_public_key_k = produce_resource
            .joint_vote_encryption_public_key_k()
            .await?;

        let v_cts_nonces = data_fields_plaintexts
            .as_Vec1_ContestDataFieldPlaintext()
            .enumerate()
            .map(|(data_field_j, &data_field_plaintext)| {
                let nonce_xi_i_j =
                    NonceFE::new_xi_i_j(field, h_i, ballot_nonce_xi_B, contest_i, data_field_j);

                let ciphertext = joint_vote_encryption_public_key_k.encrypt_to(
                    fixed_parameters,
                    nonce_xi_i_j.as_ref(),
                    data_field_plaintext,
                );

                (ciphertext, nonce_xi_i_j)
            })
            .collect();

        Ok(v_cts_nonces)
    }

    fn proof_selection_limit(
        pre_voting_data: &PreVotingData,
        csrng: &dyn Csrng,
        selection: &[(Ciphertext, NonceFE)],
        num_selections: usize,
        selection_limit: usize,
    ) -> EgResult<ProofRange> {
        let (combined_ct, combined_nonce) = Self::sum_selection_nonce_vector(
            pre_voting_data.election_parameters().fixed_parameters(),
            selection,
        );

        Ok(ProofRange::new(
            pre_voting_data,
            csrng,
            &combined_ct,
            &combined_nonce,
            num_selections,
            selection_limit,
        )?)
    }

    /// Verify the proof that the selection limit is satisfied.
    fn verify_contest_selection_limit(
        &self,
        pre_voting_data: &PreVotingData,
        effective_contest_selection_limit: EffectiveContestSelectionLimit,
    ) -> EgResult<()> {
        let combined_ct = self.sum_selection_vector(pre_voting_data);

        let verified = ProofRange::verify(
            &self.proof_selection_limit,
            pre_voting_data,
            &combined_ct,
            effective_contest_selection_limit.into(),
        );

        if !verified {
            return Err(
                EgError::BallotContestFieldCiphertextDoesNotVerify_ContestSelectionLimit {
                    contest_ix: self.contest_ix,
                    effective_contest_selection_limit: effective_contest_selection_limit.into(),
                },
            );
        }

        Ok(())
    }

    /// Sum up the encrypted votes on a contest and their nonces. The sum of the nonces can be used
    /// to proof properties about the sum of the ciphertexts, e.g. that it satisfies the selection
    /// limit.
    pub fn sum_selection_nonce_vector(
        fixed_parameters: &FixedParameters,
        selection_with_nonces: &[(Ciphertext, NonceFE)],
    ) -> (Ciphertext, NonceFE) {
        let group = fixed_parameters.group();
        let field = fixed_parameters.field();

        let mut sum_ct = Ciphertext::one();
        let mut sum_nonce_fe = FieldElement::zero();

        for (ct, nonce) in selection_with_nonces {
            sum_ct.alpha = sum_ct.alpha.mul(&ct.alpha, group);
            sum_ct.beta = sum_ct.beta.mul(&ct.beta, group);
            sum_nonce_fe = sum_nonce_fe.add(nonce.as_ref(), field);
        }

        (sum_ct, NonceFE::from_field_element(sum_nonce_fe))
    }

    /// Sum up the encrypted votes on a contest. The sum is needed when checking that the selection
    /// limit is satisfied.
    pub fn sum_selection_vector(&self, pre_voting_data: &PreVotingData) -> Ciphertext {
        let group = pre_voting_data
            .election_parameters()
            .fixed_parameters()
            .group();

        let mut sum_ct = Ciphertext::one();
        for ct in self.ciphertexts.iter() {
            sum_ct.alpha = sum_ct.alpha.mul(&ct.alpha, group);
            sum_ct.beta = sum_ct.beta.mul(&ct.beta, group);
        }

        sum_ct
    }

    /// Verify the proof that each encrypted vote is an encryption of 0 or 1,
    /// and that the selection limit is satisfied.
    pub async fn verify_proofs_for_all_data_fields_in_contest(
        &self,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<()> {
        let pre_voting_data = produce_resource.pre_voting_data().await?;
        let pre_voting_data = pre_voting_data.as_ref();

        let election_manifest = produce_resource.election_manifest().await?;
        let election_manifest = election_manifest.as_ref();

        let contest =
            election_manifest.get_contest_without_checking_ballot_style(self.contest_ix)?;

        let cnt_data_fields_in_contest = contest.qty_data_fields();

        let mut cnt_ciphertexts_verified = 0;
        for (ciphertext_ix, ciphertext) in self.ciphertexts.enumerate() {
            let contest_option = contest.get_contest_option(ciphertext_ix)?;

            let proof = self.proof_ballot_correctness.get(ciphertext_ix).ok_or(
                EgError::BallotContestFieldCiphertextDoesNotVerify_ProofNotPresent {
                    contest_ix: self.contest_ix,
                    ciphertext_ix,
                },
            )?;

            let effective_option_selection_limit =
                contest_option.effective_selection_limit(contest)?;

            ciphertext.verify_ballot_correctness(
                pre_voting_data,
                proof,
                effective_option_selection_limit,
                self.contest_ix,
                ciphertext_ix,
            )?;

            cnt_ciphertexts_verified += 1;
        }

        if cnt_ciphertexts_verified != cnt_data_fields_in_contest {
            return Err(
                EgError::BallotContestFieldCiphertextDoesNotVerify_WrongNumberOfCiphertextProofs {
                    contest_ix: self.contest_ix,
                    cnt_ciphertexts_verified,
                    cnt_data_fields_in_contest,
                },
            );
        }

        let effective_contest_selection_limit = contest.effective_contest_selection_limit()?;

        self.verify_contest_selection_limit(pre_voting_data, effective_contest_selection_limit)?;

        Ok(())
    }

    //? TODO move to `contest_encrypted_scaled.rs`
    /// Scales all the encrypted votes on the contest by the same factor.
    pub fn scale(
        &self,
        fixed_parameters: &FixedParameters,
        factor: &FieldElement,
    ) -> ContestEncryptedScaled {
        let selection = self
            .ciphertexts
            .iter()
            .map(|ct| ct.scale(fixed_parameters, factor))
            .collect();
        ContestEncryptedScaled { selection }
    }

    pub fn ciphertexts_len(&self) -> usize {
        self.ciphertexts.len()
    }

    pub fn ciphertexts_as_slice(&self) -> &[Ciphertext] {
        self.ciphertexts.as_slice()
    }
}
