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
    joint_election_public_key::{Ciphertext, Nonce},
    vec1::Vec1,
    zk::{ProofRange, ProofRangeError},
};

use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

use crate::{ballot_encrypting_tool::BallotEncryptingTool, nonce::option_nonce};

/// A 1-based index of a [`ContestSelectionPreEncrypted`] in the order it is defined in the [`crate::contest::ContestPreEncrypted`].
pub type ContestSelectionPreEncryptedIndex = Index<ContestSelectionPreEncrypted>;

/// A contest option in a pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestSelectionPreEncrypted {
    /// The index of this pre-encrypted contest selection in the pre-encrypted contest.
    pub index: ContestSelectionPreEncryptedIndex,

    /// Vector of ciphertexts used to represent the selection.
    #[serde(skip)]
    pub selections: Vec<(Ciphertext, Option<Nonce>)>,

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
            self.selections[k].1 = Some(Nonce::new(option_nonce(
                &device.header,
                primary_nonce,
                contest_index,
                j,
                ContestOptionIndex::from_one_based_index(k as u32).unwrap(),
            )));
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
            let ciphertext = pvd.public_key.encrypt_with(
                &pvd.parameters.fixed_parameters,
                &nonce,
                (j == k) as usize,
            );
            let maybe_nonce = if store_nonces {
                Some(Nonce::new(nonce))
            } else {
                None
            };
            selections.push((ciphertext, maybe_nonce))
        }
        let only_ciphertexts: Vec<Ciphertext> =
            selections.iter().map(|(ct, _)| ct.clone()).collect();
        let selection_hash = BallotEncryptingTool::selection_hash(pvd, &only_ciphertexts);

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
            let ciphertext =
                pvd.public_key
                    .encrypt_with(&pvd.parameters.fixed_parameters, &nonce, 0);
            let maybe_nonce = if store_nonces {
                Some(Nonce::new(nonce))
            } else {
                None
            };
            selections.push((ciphertext, maybe_nonce));
        }
        let only_ciphertexts: Vec<Ciphertext> =
            selections.iter().map(|(ct, _)| ct.clone()).collect();

        let selection_hash = BallotEncryptingTool::selection_hash(pvd, &only_ciphertexts);
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
    ) -> Result<Vec1<ProofRange>, ProofRangeError> {
        let mut proofs = Vec1::new();
        // for (i, selection) in self.selections.iter().enumerate() {
        for (i, c) in self.selections.iter().enumerate() {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let nonce = c.1.as_ref().unwrap();
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            proofs
                .try_push(c.0.proof_ballot_correctness(pvd, csprng, sequence_order == i, nonce)?)
                .unwrap();
        }
        Ok(proofs)
    }
}
