// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use serde::{Deserialize, Serialize};
use util::{algebra::FieldElement, csprng::Csprng};

use crate::{
    contest_hash,
    contest_selection::ContestSelection,
    device::Device,
    election_manifest::{Contest, ContestIndex, ContestOptionIndex},
    election_record::PreVotingData,
    fixed_parameters::FixedParameters,
    hash::HValue,
    index::Index,
    joint_election_public_key::{Ciphertext, Nonce},
    nonce::encrypted as nonce,
    vec1::Vec1,
    zk::{ProofRange, ProofRangeError},
};

/// A 1-based index of a [`ContestEncrypted`] in the order it is defined in the [`crate::ballot::BallotEncrypted`].
pub type ContestEncryptedIndex = Index<ContestEncrypted>;

/// A contest in an encrypted ballot.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContestEncrypted {
    /// Encrypted voter selection vector.
    pub selection: Vec<Ciphertext>,

    /// Contest hash.
    pub contest_hash: HValue,

    /// Proof of ballot correctness.
    pub proof_ballot_correctness: Vec1<ProofRange>,

    // Proof of satisfying the selection limit.
    pub proof_selection_limit: ProofRange,
}

/// A scaled version of [`ContestEncrypted`]. This means that each encrypted vote on the contest
/// has been scaled by a factor. It is trusted that the encrypted ciphertexts in a
/// [`ScaledContestEncrypted`] really are the ones from a [`ContestEncrypted`] scaled by a factor.
/// Contains no proofs.
#[derive(PartialEq, Eq)]
pub struct ScaledContestEncrypted {
    /// Scaled encrypted voter selection vector.
    pub selection: Vec<Ciphertext>,
}

impl ScaledContestEncrypted {
    /// Verify that the [`ScaledContestEncrypted`] stems from a given [`ContestEncrypted`] by
    /// scaling with a given factor.
    pub fn verify(
        &self,
        origin: ContestEncrypted,
        factor: &FieldElement,
        fixed_parameters: &FixedParameters,
    ) -> bool {
        origin.scale(fixed_parameters, factor) == *self
    }
}

impl ContestEncrypted {
    fn encrypt_selection(
        header: &PreVotingData,
        primary_nonce: &[u8],
        contest_index: ContestIndex,
        pt_vote: &ContestSelection,
    ) -> Vec<(Ciphertext, Nonce)> {
        // TODO: Check if selection limit is satisfied

        let mut vote: Vec<(Ciphertext, Nonce)> = Vec::new();
        for j in 1..=pt_vote.get_vote().len() {
            // This is fine since 1 <= j <= Index::VALID_MAX_U32
            let o_idx = ContestOptionIndex::from_one_based_index_unchecked(j as u32);
            let nonce = nonce(header, primary_nonce, contest_index, o_idx);
            vote.push((
                header.public_key.encrypt_with(
                    &header.parameters.fixed_parameters,
                    &nonce,
                    pt_vote.get_vote()[j - 1] as usize,
                ),
                Nonce::new(nonce),
            ));
        }
        vote
    }

    pub fn new(
        device: &Device,
        csprng: &mut Csprng,
        primary_nonce: &[u8],
        contest: &Contest,
        contest_index: ContestIndex,
        pt_vote: &ContestSelection,
    ) -> Result<ContestEncrypted, ProofRangeError> {
        let selection_and_nonce =
            Self::encrypt_selection(&device.header, primary_nonce, contest_index, pt_vote);
        let selection = selection_and_nonce
            .iter()
            .map(|(ct, _)| ct.clone())
            .collect::<Vec<_>>();
        let contest_hash = contest_hash::contest_hash(&device.header, contest_index, &selection);

        let mut proof_ballot_correctness = Vec1::new();
        for (i, (sel, nonce)) in selection_and_nonce.iter().enumerate() {
            // This is OK, since selection_and_nonce.len() = pt_vote.vote.len() which
            // is guaranteed to not exceed the size of a `Index<T>` by how a `ContestSelection` is
            // constructed.
            proof_ballot_correctness.push_unchecked(sel.proof_ballot_correctness(
                &device.header,
                csprng,
                pt_vote.get_vote()[i] == 1u8,
                nonce,
            )?);
        }

        let mut num_selections = 0;
        pt_vote.get_vote().iter().for_each(|v| num_selections += v);
        let proof_selection_limit = ContestEncrypted::proof_selection_limit(
            &device.header,
            csprng,
            &selection_and_nonce,
            num_selections as usize,
            contest.selection_limit,
        )?;
        Ok(ContestEncrypted {
            selection,
            contest_hash,
            proof_ballot_correctness,
            proof_selection_limit,
        })
    }

    pub fn get_proof_ballot_correctness(&self) -> &Vec1<ProofRange> {
        &self.proof_ballot_correctness
    }

    pub fn get_proof_selection_limit(&self) -> &ProofRange {
        &self.proof_selection_limit
    }

    pub fn proof_selection_limit(
        header: &PreVotingData,
        csprng: &mut Csprng,
        selection: &[(Ciphertext, Nonce)],
        num_selections: usize,
        selection_limit: usize,
    ) -> Result<ProofRange, ProofRangeError> {
        let (combined_ct, combined_nonce) =
            Self::sum_selection_nonce_vector(&header.parameters.fixed_parameters, selection);
        ProofRange::new(
            header,
            csprng,
            &combined_ct,
            &combined_nonce,
            num_selections,
            selection_limit,
        )
    }

    /// Verify the proof that the selection limit is satisfied.
    fn verify_selection_limit(&self, header: &PreVotingData, selection_limit: usize) -> bool {
        let combined_ct =
            Self::sum_selection_vector(&header.parameters.fixed_parameters, &self.selection);
        ProofRange::verify(
            &self.proof_selection_limit,
            header,
            &combined_ct,
            selection_limit,
        )
    }

    /// Sum up the encrypted votes on a contest and their nonces. The sum of the nonces can be used
    /// to proof properties about the sum of the ciphertexts, e.g. that it satisfies the selection
    /// limit.
    pub fn sum_selection_nonce_vector(
        fixed_parameters: &FixedParameters,
        selection_with_nonces: &[(Ciphertext, Nonce)],
    ) -> (Ciphertext, Nonce) {
        let group = &fixed_parameters.group;
        let field = &fixed_parameters.field;

        let mut sum_ct = Ciphertext::one();
        let mut sum_nonce = Nonce::zero();

        for (sel, nonce) in selection_with_nonces {
            sum_ct.alpha = sum_ct.alpha.mul(&sel.alpha, group);
            sum_ct.beta = sum_ct.beta.mul(&sel.beta, group);
            sum_nonce.xi = sum_nonce.xi.add(&nonce.xi, field);
        }

        (sum_ct, sum_nonce)
    }

    /// Sum up the encrypted votes on a contest. The sum is needed when checking that the selection
    /// limit is satisfied.
    pub fn sum_selection_vector(
        fixed_parameters: &FixedParameters,
        selection: &[Ciphertext],
    ) -> Ciphertext {
        let group = &fixed_parameters.group;

        let mut sum_ct = Ciphertext::one();
        for sel in selection {
            sum_ct.alpha = sum_ct.alpha.mul(&sel.alpha, group);
            sum_ct.beta = sum_ct.beta.mul(&sel.beta, group);
        }

        sum_ct
    }

    /// Verify the proof that each encrypted vote is an encryption of 0 or 1,
    /// and that the selection limit is satisfied.
    pub fn verify(&self, header: &PreVotingData, selection_limit: usize) -> bool {
        for (ct, j) in self.selection.iter().zip(1..) {
            let Ok(idx) = Index::from_one_based_index(j) else {
                return false;
            };
            let Some(proof) = self.proof_ballot_correctness.get(idx) else {
                return false;
            };
            if !ct.verify_ballot_correctness(header, proof) {
                return false;
            }
        }

        self.verify_selection_limit(header, selection_limit)
    }

    /// Scales all the encrypted votes on the contest by the same factor.
    pub fn scale(
        &self,
        fixed_parameters: &FixedParameters,
        factor: &FieldElement,
    ) -> ScaledContestEncrypted {
        let selection = self
            .selection
            .iter()
            .map(|ct| ct.scale(fixed_parameters, factor))
            .collect();
        ScaledContestEncrypted { selection }
    }
}
