// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use serde::{Deserialize, Serialize};

use util::{csprng::Csprng, prime::BigUintPrime};

use crate::{
    election_record::PreVotingData, index::Index, joint_election_public_key::Ciphertext,
    zk::ProofRange,
};

// An encrypted option in a contest.
// #[derive(Debug, Clone)]
// pub struct ContestSelectionCiphertext {
//     /// Ciphertext
//     pub ciphertext: Ciphertext,
//     // TODO: Probably shouldn't be here
//     // Nonce used to produce the ciphertext
//     // pub nonce: BigUint,
// }

pub type ContestSelectionPlaintext = u8;

// /// A 1-based index of a [`ContestSelectionPlaintext`] in the order it is defined in the [`crate::election_manifest::ElectionManifest`].
// pub type ContestSelectionPlaintextIndex = Index<ContestSelectionPlaintext>;

/// A 1-based index of a [`ContestSelection`].
pub type ContestSelectionIndex = Index<ContestSelection>;

/// A contest selection by a voter.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestSelection {
    /// Vector used to represent the selection
    pub vote: Vec<ContestSelectionPlaintext>,
}

impl ContestSelection {
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

    // Choices are 1-indexed
    // pub fn new_unchecked(choices: Vec<u32>, num_options: usize) -> Self {
    //     let mut vote = Vec::new();
    //     for _ in 0..num_options {
    //         vote.try_push(0).unwrap();
    //     }

    //     for choice in choices {
    //         let idx = <Index<u8>>::from_one_based_index(choice).unwrap();
    //         *vote.get_mut(idx).unwrap() = 1u8;
    //     }

    //     Self { vote }
    // }
}

impl Ciphertext {
    pub fn proof_ballot_correctness(
        &self,
        header: &PreVotingData,
        csprng: &mut Csprng,
        selected: bool,
        q: &BigUintPrime,
    ) -> ProofRange {
        ProofRange::new(header, csprng, q, self, selected as usize, 1)
    }
}

// /// Serialize for CiphertextContestSelection
// impl Serialize for ContestSelectionCiphertext {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::ser::Serializer,
//     {
//         self.ciphertext.clone().serialize(serializer)
//     }
// }

// impl<'de> Deserialize<'de> for ContestSelectionCiphertext {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         match Ciphertext::deserialize(deserializer) {
//             Ok(ciphertext) => Ok(ContestSelectionCiphertext {
//                 ciphertext,
//                 nonce: BigUint::from(0 as u8),
//             }),
//             Err(e) => Err(e),
//         }
//     }
// }
