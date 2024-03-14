// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use eg::{
    contest_encrypted::ContestEncrypted,
    contest_selection::ContestSelectionPlaintext,
    device::Device,
    election_manifest::{Contest, ContestIndex, ContestOptionIndex},
    election_record::PreVotingData,
    fixed_parameters::FixedParameters,
    hash::HValue,
    index::Index,
    joint_election_public_key::{Ciphertext, Nonce},
    vec1::{HasIndexType, HasIndexTypeMarker, Vec1},
    zk::{ProofRange, ProofRangeError},
};
use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

use crate::{
    contest_hash::contest_hash,
    contest_selection::{ContestSelectionPreEncrypted, ContestSelectionPreEncryptedIndex},
};

/// A 1-based index of a [`ContestPreEncrypted`] in the order it is defined in the [`crate::ballot::BallotPreEncrypted`].
pub type ContestPreEncryptedIndex = Index<ContestPreEncrypted>;

/// A contest in a pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestPreEncrypted {
    /// Index of the contest in the election manifest.
    pub contest_index: ContestIndex,

    /// Selections in this contest.
    pub selections: Vec1<ContestSelectionPreEncrypted>,

    /// Contest hash
    #[serde(skip)]
    pub contest_hash: HValue,
}

impl HasIndexType for ContestPreEncrypted {
    type IndexType = Contest;
}
impl HasIndexTypeMarker for ContestSelectionPreEncrypted {}

impl PartialEq for ContestPreEncrypted {
    fn eq(&self, other: &Self) -> bool {
        self.contest_index == other.contest_index && self.selections == other.selections
    }
}

impl ContestPreEncrypted {
    pub fn regenerate_nonces(&mut self, device: &Device, primary_nonce: &[u8]) {
        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        self.selections.indices().for_each(|j| {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            self.selections.get_mut(j).unwrap().regenerate_nonces(
                device,
                primary_nonce,
                self.contest_index,
                ContestOptionIndex::from_one_based_index(j.get_one_based_usize() as u32).unwrap(),
            );
        });
    }

    pub fn new(
        pvd: &PreVotingData,
        primary_nonce: &[u8],
        store_nonces: bool,
        contest: &Contest,
        contest_index: ContestIndex,
    ) -> ContestPreEncrypted {
        let mut selections = <Vec1<ContestSelectionPreEncrypted>>::new();
        let num_selections = contest.options.len() + contest.selection_limit;

        for j in 1..contest.options.len() + 1 {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let selection = ContestSelectionPreEncrypted::new(
                pvd,
                primary_nonce,
                store_nonces,
                contest_index,
                ContestOptionIndex::from_one_based_index(j as u32).unwrap(),
                num_selections,
            );
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            selections.try_push(selection).unwrap();
        }

        for j in 0..contest.selection_limit {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let selection = ContestSelectionPreEncrypted::new_null(
                pvd,
                primary_nonce,
                store_nonces,
                contest_index,
                ContestOptionIndex::from_one_based_index((contest.options.len() + j + 1) as u32)
                    .unwrap(),
                num_selections,
            );
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            selections.try_push(selection).unwrap();
        }

        let contest_hash = contest_hash(pvd, contest_index, &selections);
        ContestPreEncrypted {
            contest_index,
            selections,
            contest_hash,
        }
    }

    pub fn proof_ballot_correctness(
        &self,
        pvd: &PreVotingData,
        csprng: &mut Csprng,
    ) -> Result<Vec1<Vec1<ProofRange>>, ProofRangeError> {
        let mut proofs = Vec1::new();
        for i in self.selections.indices() {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let selection = self.selections.get(i).unwrap();
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            proofs
                .try_push(selection.proof_ballot_correctness(
                    pvd,
                    csprng,
                    i.get_one_based_usize(),
                )?)
                .unwrap();
        }
        Ok(proofs)
    }

    pub fn combine_voter_selections(
        &self,
        fixed_parameters: &FixedParameters,
        voter_selections: &[ContestSelectionPlaintext],
        selection_limit: usize,
    ) -> Vec<(Ciphertext, Nonce)> {
        assert!(voter_selections.len() + selection_limit == self.selections.len());

        let field = &fixed_parameters.field;
        let group = &fixed_parameters.group;

        let mut selections = <Vec<&Vec<(Ciphertext, Option<Nonce>)>>>::new();

        voter_selections.iter().enumerate().for_each(|(i, v)| {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let i =
                ContestSelectionPreEncryptedIndex::from_one_based_index((i + 1) as u32).unwrap();
            if *v == 1 {
                #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
                selections.push(&self.selections.get(i).unwrap().selections);
            }
        });

        let mut i = self.selections.len();
        while selections.len() < selection_limit {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let idx = ContestSelectionPreEncryptedIndex::from_one_based_index(i as u32).unwrap();
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            selections.push(&self.selections.get(idx).unwrap().selections);
            i -= 1;
        }

        assert!(selections.len() == selection_limit);

        let mut combined_selection = selections[0].clone();

        #[allow(clippy::needless_range_loop)]
        for i in 1..selections.len() {
            for j in 0..combined_selection.len() {
                let combined_selection_j = &mut combined_selection[j];
                let selections_i_j = &selections[i][j];

                combined_selection_j.0.alpha = combined_selection_j
                    .0
                    .alpha
                    .mul(&selections_i_j.0.alpha, group);
                combined_selection_j.0.beta = combined_selection_j
                    .0
                    .beta
                    .mul(&selections_i_j.0.beta, group);

                #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
                let cs_j_nonce = combined_selection_j
                    .1
                    .as_ref()
                    .unwrap()
                    .xi
                    .add(&selections_i_j.1.as_ref().unwrap().xi, field);
                combined_selection_j.1 = Some(Nonce::new(cs_j_nonce));
            }
        }
        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        combined_selection
            .iter()
            .map(|(ct, maybe_nonce)| (ct.clone(), maybe_nonce.as_ref().unwrap().clone()))
            .collect()
    }

    pub fn finalize(
        &self,
        device: &Device,
        csprng: &mut Csprng,
        voter_selections: &[u8],
        selection_limit: usize,
        num_options: usize,
    ) -> Result<ContestEncrypted, ProofRangeError> {
        let selection = self.combine_voter_selections(
            &device.header.parameters.fixed_parameters,
            voter_selections,
            selection_limit,
        );

        let mut proof_ballot_correctness = Vec1::new();
        assert!(num_options == voter_selections.len());

        for i in 0..num_options {
            let nonce = &selection[i].1;
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            proof_ballot_correctness
                .try_push(selection[i].0.proof_ballot_correctness(
                    &device.header,
                    csprng,
                    voter_selections[i] == 1u8,
                    nonce,
                )?)
                .unwrap();
        }

        let mut num_selections = 0;
        voter_selections.iter().for_each(|v| num_selections += v);

        let proof_selection_limit = ContestEncrypted::proof_selection_limit(
            &device.header,
            csprng,
            &selection,
            num_selections as usize,
            selection_limit,
        )?;
        let selection = selection.iter().map(|(ct, _)| ct.clone()).collect();

        // TODO: Change crypto hash
        Ok(ContestEncrypted {
            selection,
            contest_hash: self.contest_hash,
            proof_ballot_correctness,
            proof_selection_limit,
        })
    }
}
