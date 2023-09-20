// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use eg::{
    device::Device,
    election_manifest::{ContestIndex, ContestOptionIndex},
    election_record::PreVotingData,
    hash::HValue,
    index::Index,
    joint_election_public_key::Ciphertext,
    vec1::Vec1,
    zk::ProofRange,
};

use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, prime::BigUintPrime};

use crate::{ballot_encrypting_tool::BallotEncryptingTool, nonce::option_nonce};

/// A 1-based index of a [`ContestSelectionPreEncrypted`] in the order it is defined in the [`ContestPreEncrypted`].
pub type ContestSelectionPreEncryptedIndex = Index<ContestSelectionPreEncrypted>;

/// A contest option in a pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestSelectionPreEncrypted {
    /// The index of this pre-encrypted contest selection in the pre-encrypted contest.
    pub index: ContestSelectionPreEncryptedIndex,

    /// Vector of ciphertexts used to represent the selection.
    #[serde(skip)]
    pub selections: Vec<Ciphertext>,

    /// Selection hash.
    #[serde(skip)]
    pub selection_hash: HValue,

    /// Shortcode for this selection.
    pub shortcode: String,
}

impl PartialEq for ContestSelectionPreEncrypted {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.shortcode == other.shortcode
    }
}

impl ContestSelectionPreEncrypted {
    pub fn regenerate_nonces(
        &mut self,
        device: &Device,
        primary_nonce: &[u8],
        contest_index: ContestIndex,
        j: ContestOptionIndex,
    ) {
        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        for k in 1..self.selections.len() + 1 {
            self.selections[k].nonce = Some(option_nonce(
                &device.header,
                primary_nonce,
                contest_index,
                j,
                ContestOptionIndex::from_one_based_index(k as u32).unwrap(),
            ));
        }
    }

    pub fn new(
        pvd: &PreVotingData,
        primary_nonce: &[u8],
        store_nonces: bool,
        contest_index: ContestIndex,
        j: ContestOptionIndex,
        num_selections: usize,
    ) -> ContestSelectionPreEncrypted {
        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        let index =
            ContestSelectionPreEncryptedIndex::from_one_based_index(j.get_one_based_u32()).unwrap();

        let mut selections = Vec::new();
        for k in 1..num_selections + 1 {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let k = ContestOptionIndex::from_one_based_index(k as u32).unwrap();
            let nonce = option_nonce(pvd, primary_nonce, contest_index, j, k);
            selections.push(pvd.public_key.encrypt_with(
                &pvd.parameters.fixed_parameters,
                &nonce,
                (j == k) as usize,
                store_nonces,
            ))
        }

        let selection_hash = BallotEncryptingTool::selection_hash(pvd, &selections);

        // Generate pre-encrypted votes for each possible (single) choice
        ContestSelectionPreEncrypted {
            index,
            selections,
            selection_hash,
            shortcode: BallotEncryptingTool::short_code_last_byte(&selection_hash),
        }
    }

    pub fn new_null(
        pvd: &PreVotingData,
        primary_nonce: &[u8],
        store_nonces: bool,
        contest_index: ContestIndex,
        null_index: ContestOptionIndex,
        num_selections: usize,
    ) -> ContestSelectionPreEncrypted {
        let mut selections = Vec::new();
        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        let index =
            ContestSelectionPreEncryptedIndex::from_one_based_index(null_index.get_one_based_u32())
                .unwrap();
        for k in 1..num_selections + 1 {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let k = ContestOptionIndex::from_one_based_index(k as u32).unwrap();
            let nonce = option_nonce(pvd, primary_nonce, contest_index, null_index, k);
            selections.push(pvd.public_key.encrypt_with(
                &pvd.parameters.fixed_parameters,
                &nonce,
                0,
                store_nonces,
            ));
        }

        let selection_hash = BallotEncryptingTool::selection_hash(pvd, &selections);
        let shortcode = BallotEncryptingTool::short_code_last_byte(&selection_hash);
        ContestSelectionPreEncrypted {
            index,
            selections,
            selection_hash,
            shortcode,
        }
    }

    // TODO: Fix type of sequence_order
    pub fn proof_ballot_correctness(
        &self,
        pvd: &PreVotingData,
        csprng: &mut Csprng,
        sequence_order: usize,
        q: &BigUintPrime,
    ) -> Vec1<ProofRange> {
        let mut proofs = Vec1::new();
        // for (i, selection) in self.selections.iter().enumerate() {
        self.selections.iter().enumerate().for_each(|(i, c)| {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            proofs
                .try_push(c.proof_ballot_correctness(pvd, csprng, sequence_order == i, q))
                .unwrap();
        });
        proofs
    }
}
