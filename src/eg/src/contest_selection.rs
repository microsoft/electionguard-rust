use serde::{Deserialize, Serialize};
use std::rc::Rc;
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{
    election_record::PreVotingData, index::GenericIndex, joint_election_public_key::Ciphertext,
    vec1::Vec1, zk::ProofRange,
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

/// A 1-based index of a [`ContestSelection`] in the order it is defined in the [`BallotPlaintext`].
pub type ContestSelectionPlaintextIndex = GenericIndex<ContestSelectionPlaintext>;

/// A 1-based index of a [`ContestSelection`] in the order it is defined in the [`BallotPlaintext`].
pub type ContestSelectionIndex = GenericIndex<ContestSelection>;

/// A contest selection by a voter.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestSelection {
    /// Vector used to represent the selection
    pub vote: Vec1<ContestSelectionPlaintext>,
}

impl ContestSelection {
    pub fn new_pick_random(
        csprng: &mut Csprng,
        selection_limit: usize,
        num_options: usize,
    ) -> Self {
        let mut vote = Vec1::new();
        for _ in 0..num_options {
            vote.try_push(0).unwrap();
        }

        let selection_limit = csprng.next_u64() as usize % (selection_limit + 1);
        let mut changed = 0;

        while changed < selection_limit {
            let idx = <GenericIndex<u8>>::from_one_based_index(
                1 + csprng.next_u32() % (vote.len() as u32),
            )
            .unwrap();
            if *vote.get(idx).unwrap() == 0u8 {
                *vote.get_mut(idx).unwrap() = 1u8;
                changed += 1;
            }
        }

        Self { vote }
    }

    // Choices are 1-indexed
    pub fn new_unchecked(choices: Vec<u32>, num_options: usize) -> Self {
        let mut vote = Vec1::new();
        for _ in 0..num_options {
            vote.try_push(0).unwrap();
        }

        for choice in choices {
            let idx = <GenericIndex<u8>>::from_one_based_index(choice).unwrap();
            *vote.get_mut(idx).unwrap() = 1u8;
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
        zmulq: Rc<ZMulPrime>,
    ) -> ProofRange {
        ProofRange::new(header, csprng, zmulq, &self, selected as usize, 1)
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
