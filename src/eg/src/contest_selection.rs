use std::{collections::HashSet, rc::Rc};

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{
    ballot::BallotConfig, device::Device, fixed_parameters::FixedParameters, key::Ciphertext,
    nizk::ProofRange,
};

/// A plaintext vote for an option in a contest.
pub type ContestSelectionPlaintext = u8;

/// An encrypted option in a contest.
#[derive(Debug, Clone)]
pub struct ContestSelectionCiphertext {
    /// Ciphertext
    pub ciphertext: Ciphertext,

    /// Nonce used to produce the ciphertext
    pub nonce: BigUint,
}

/// A contest option in a pre-encrypted ballot.
#[derive(Debug, Serialize)]
pub struct ContestSelectionEncrypted {
    /// Vector of ciphertexts used to represent the selection
    pub vote: Vec<ContestSelectionCiphertext>,

    /// Selection hash
    pub crypto_hash: String,
}

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
        let mut vote = HashSet::new();
        // TODO: Allow 0 selections
        let selection_limit = 1 + (csprng.next_u64() as usize % selection_limit);

        while vote.len() < selection_limit {
            vote.insert((csprng.next_u64() as usize % num_options) as u8);
        }

        Self {
            vote: vote.into_iter().collect(),
        }
    }
}

impl ContestSelectionCiphertext {
    pub fn get_nonce(&self) -> &BigUint {
        &self.nonce
    }

    pub fn set_nonce(&mut self, nonce: BigUint) {
        self.nonce = nonce;
    }

    pub fn proof_ballot_correctness(
        &self,
        device: &Device,
        csprng: &mut Csprng,
        selected: bool,
        zmulq: Rc<ZMulPrime>,
    ) -> ProofRange {
        ProofRange::new(
            device,
            csprng,
            zmulq,
            &self.nonce,
            &self.ciphertext,
            selected as usize,
            1,
        )
    }
}

/// Serialize for CiphertextContestSelection
impl Serialize for ContestSelectionCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.ciphertext.clone().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ContestSelectionCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match Ciphertext::deserialize(deserializer) {
            Ok(ciphertext) => Ok(ContestSelectionCiphertext {
                ciphertext,
                nonce: BigUint::from(0 as u8),
            }),
            Err(e) => Err(e),
        }
    }
}
