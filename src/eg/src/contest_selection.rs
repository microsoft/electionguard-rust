// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use serde::{Deserialize, Serialize};

use util::csprng::Csprng;

use crate::{
    election_manifest::Contest,
    election_record::PreVotingData,
    index::Index,
    joint_election_public_key::{Ciphertext, Nonce},
    vec1::HasIndexType,
    zk::{ProofRange, ProofRangeError},
};

pub type ContestSelectionPlaintext = u8;

/// A 1-based index of a [`ContestSelection`].
pub type ContestSelectionIndex = Index<ContestSelection>;

/// A contest selection by a voter.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContestSelection {
    /// Vector used to represent the selection
    vote: Vec<ContestSelectionPlaintext>,
}

impl HasIndexType for ContestSelection {
    type IndexType = Contest;
}

impl ContestSelection {
    pub fn new(vote: Vec<ContestSelectionPlaintext>) -> Option<ContestSelection> {
        if vote.len() > Index::<ContestSelectionPlaintext>::VALID_MAX_USIZE {
            return None;
        }
        Some(ContestSelection { vote })
    }

    pub fn get_vote(&self) -> &[ContestSelectionPlaintext] {
        &self.vote
    }

    pub fn new_pick_random(
        csprng: &mut Csprng,
        selection_limit: usize,
        num_options: usize,
    ) -> Self {
        let mut vote = vec![0; num_options];

        let selection_limit = csprng.next_u64() as usize % (selection_limit + 1);
        let mut changed = 0;

        while changed < selection_limit {
            //TODO: a tiny bit of bias in this selection method. Better to put a proper `next_u64_lt()` on csprng.
            let idx = csprng.next_u64() as usize % vote.len();

            if vote[idx] == 0u8 {
                vote[idx] = 1u8;
                changed += 1;
            }
        }

        Self { vote }
    }
}

impl Ciphertext {
    pub fn proof_ballot_correctness(
        &self,
        header: &PreVotingData,
        csprng: &mut Csprng,
        selected: bool,
        nonce: &Nonce,
    ) -> Result<ProofRange, ProofRangeError> {
        ProofRange::new(header, csprng, self, nonce, selected as usize, 1)
    }

    /// Verify the proof that the cipher text is an encryption of 0 or 1.
    pub fn verify_ballot_correctness(&self, header: &PreVotingData, proof: &ProofRange) -> bool {
        proof.verify(header, self, 1)
    }
}
