use serde::Serialize;
use std::rc::Rc;
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{
    election_record::ElectionRecordHeader, joint_election_public_key::Ciphertext, zk::ProofRange,
};

/// A plaintext vote for an option in a contest.
pub type ContestSelectionPlaintext = u8;

// An encrypted option in a contest.
// #[derive(Debug, Clone)]
// pub struct ContestSelectionCiphertext {
//     /// Ciphertext
//     pub ciphertext: Ciphertext,
//     // TODO: Probably shouldn't be here
//     // Nonce used to produce the ciphertext
//     // pub nonce: BigUint,
// }

/// A contest selection by a voter.
#[derive(Debug, Serialize)]
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
        let mut vote = vec![0u8; num_options];

        let selection_limit = csprng.next_u64() as usize % (selection_limit + 1);
        let mut changed = 0;

        while changed < selection_limit {
            let idx = csprng.next_u32() % (vote.len() as u32);
            if vote[idx as usize] == 0 {
                vote[idx as usize] = 1;
                changed += 1;
            }
        }

        Self { vote }
    }
}

impl Ciphertext {
    pub fn proof_ballot_correctness(
        &self,
        header: &ElectionRecordHeader,
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
