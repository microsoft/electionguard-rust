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
    joint_election_public_key::Ciphertext,
    vec1::{HasIndexType, HasIndexTypeMarker, Vec1},
    zk::ProofRange,
};
use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

use crate::{
    contest_hash::contest_hash,
    contest_selection::{ContestSelectionPreEncrypted, ContestSelectionPreEncryptedIndex},
};

/// A 1-based index of a [`ContestPreEncrypted`] in the order it is defined in the [`BallotPreEncrypted`].
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
    ) -> Vec1<Vec1<ProofRange>> {
        let mut proofs = Vec1::new();
        self.selections.indices().for_each(|i| {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let selection = self.selections.get(i).unwrap();
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            proofs
                .try_push(selection.proof_ballot_correctness(pvd, csprng, i.get_one_based_usize()))
                .unwrap();
        });
        proofs
    }

    pub fn combine_voter_selections(
        &self,
        fixed_parameters: &FixedParameters,
        voter_selections: &Vec<ContestSelectionPlaintext>,
        selection_limit: usize,
    ) -> Vec<Ciphertext> {
        assert!(voter_selections.len() + selection_limit == self.selections.len());

        let field = &fixed_parameters.field;
        let group = &fixed_parameters.group;

        let mut selections = <Vec<&Vec<Ciphertext>>>::new();

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

                combined_selection_j.alpha =
                    combined_selection_j.alpha.mul(&selections_i_j.alpha, group);
                combined_selection_j.beta =
                    combined_selection_j.beta.mul(&selections_i_j.beta, group);

                #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
                let cs_j_nonce = combined_selection_j
                    .nonce
                    .as_ref()
                    .unwrap()
                    .add(selections_i_j.nonce.as_ref().unwrap(), field);
                combined_selection_j.nonce = Some(cs_j_nonce);
            }
        }
        combined_selection
    }

    pub fn finalize(
        &self,
        device: &Device,
        csprng: &mut Csprng,
        voter_selections: &Vec<u8>,
        selection_limit: usize,
        num_options: usize,
    ) -> ContestEncrypted {
        let selection = self.combine_voter_selections(
            &device.header.parameters.fixed_parameters,
            voter_selections,
            selection_limit,
        );

        let mut proof_ballot_correctness = Vec1::new();
        assert!(num_options == voter_selections.len());

        for i in 0..num_options {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            proof_ballot_correctness
                .try_push(selection[i].proof_ballot_correctness(
                    &device.header,
                    csprng,
                    voter_selections[i] == 1u8,
                ))
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
        );

        // TODO: Change crypto hash
        ContestEncrypted {
            selection,
            contest_hash: self.contest_hash,
            proof_ballot_correctness,
            proof_selection_limit,
        }
    }
}
