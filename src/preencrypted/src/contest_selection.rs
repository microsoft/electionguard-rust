use std::rc::Rc;

use eg::{
    device::Device,
    election_manifest::ContestOption,
    election_record::PreVotingData,
    hash::HValue,
    index::GenericIndex,
    joint_election_public_key::{Ciphertext, CiphertextIndex},
    vec1::Vec1,
    zk::ProofRange,
};

use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{ballot_encrypting_tool::BallotEncryptingTool, nonce::option_nonce};

/// A 1-based index of a [`ContestSelectionPreEncrypted`] in the order it is defined in the [`ContestPreEncrypted`].
pub type ContestSelectionPreEncryptedIndex = GenericIndex<ContestSelectionPreEncrypted>;

/// A contest option in a pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestSelectionPreEncrypted {
    /// Label.
    pub label: String,

    /// Vector of ciphertexts used to represent the selection.
    #[serde(skip)]
    pub selections: Vec1<Ciphertext>,

    /// Selection hash.
    #[serde(skip)]
    pub selection_hash: HValue,

    /// Shortcode for this selection.
    pub shortcode: String,
}

impl PartialEq for ContestSelectionPreEncrypted {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label && self.shortcode == other.shortcode
    }
}

impl ContestSelectionPreEncrypted {
    pub fn regenerate_nonces(
        &mut self,
        device: &Device,
        primary_nonce: &[u8],
        contest_label: &String,
        selection_labels: &Vec1<String>,
        j: GenericIndex<String>,
    ) {
        for k in 1..self.selections.len() + 1 {
            let c_idx = CiphertextIndex::from_one_based_index(k as u32).unwrap();
            let s_idx = <GenericIndex<String>>::from_one_based_index(k as u32).unwrap();
            self.selections.get_mut(c_idx).unwrap().nonce = Some(option_nonce(
                &device.header,
                primary_nonce,
                contest_label.as_bytes(),
                selection_labels.get(j).unwrap().as_bytes(),
                selection_labels.get(s_idx).unwrap().as_bytes(),
            ));
        }
    }

    pub fn new(
        pvd: &PreVotingData,
        primary_nonce: &[u8],
        store_nonces: bool,
        selection: &ContestOption,
        contest_label: &String,
        selection_labels: &Vec1<String>,
        j: GenericIndex<String>,
    ) -> ContestSelectionPreEncrypted {
        let length = selection_labels.len();
        assert!(selection_labels.len() == length);
        let label = selection.label.clone();

        let mut selections = Vec1::new();
        for k in 1..length + 1 {
            let k = <GenericIndex<String>>::from_one_based_index(k as u32).unwrap();
            let nonce = option_nonce(
                pvd,
                primary_nonce,
                contest_label.as_bytes(),
                selection_labels.get(j).unwrap().as_bytes(),
                selection_labels.get(k).unwrap().as_bytes(),
            );
            selections
                .try_push(pvd.public_key.encrypt_with(
                    &pvd.parameters.fixed_parameters,
                    &nonce,
                    (j.get_one_based_usize() == k.get_one_based_usize()) as usize,
                    store_nonces,
                ))
                .unwrap();
        }

        let selection_hash = BallotEncryptingTool::selection_hash(&pvd, &selections);

        // Generate pre-encrypted votes for each possible (single) choice
        ContestSelectionPreEncrypted {
            label,
            selections,
            selection_hash,
            shortcode: BallotEncryptingTool::short_code_last_byte(&selection_hash),
        }
    }

    pub fn new_null(
        pvd: &PreVotingData,
        primary_nonce: &[u8],
        store_nonces: bool,
        contest_label: &str,
        selection_labels: &Vec1<String>,
        null_label: &str,
    ) -> ContestSelectionPreEncrypted {
        let mut selections = Vec1::new();
        for k in 1..selection_labels.len() + 1 {
            let k = <GenericIndex<String>>::from_one_based_index(k as u32).unwrap();
            let nonce = option_nonce(
                pvd,
                primary_nonce,
                contest_label.as_bytes(),
                null_label.as_bytes(),
                selection_labels.get(k).unwrap().as_bytes(),
            );
            selections
                .try_push(pvd.public_key.encrypt_with(
                    &pvd.parameters.fixed_parameters,
                    &nonce,
                    0,
                    store_nonces,
                ))
                .unwrap();
        }

        let selection_hash = BallotEncryptingTool::selection_hash(pvd, &selections);
        let shortcode = BallotEncryptingTool::short_code_last_byte(&selection_hash);
        ContestSelectionPreEncrypted {
            label: null_label.to_string(),
            selections,
            selection_hash,
            shortcode,
        }
    }

    // TODO: Fix type of sequence_order
    pub fn proof_ballot_correctness(
        &self,
        header: &PreVotingData,
        csprng: &mut Csprng,
        sequence_order: usize,
        zmulq: Rc<ZMulPrime>,
    ) -> Vec1<ProofRange> {
        let mut proofs = Vec1::new();
        // for (i, selection) in self.selections.iter().enumerate() {
        self.selections.indices().for_each(|i| {
            proofs
                .try_push(self.selections.get(i).unwrap().proof_ballot_correctness(
                    header,
                    csprng,
                    sequence_order == i.get_zero_based_usize(),
                    zmulq.clone(),
                ))
                .unwrap();
        });
        proofs
    }
}
