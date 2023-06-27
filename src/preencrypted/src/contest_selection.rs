use std::rc::Rc;

use eg::{
    contest::ContestOption, device::Device, election_record::ElectionRecordHeader, hash::HValue,
    joint_election_public_key::Ciphertext, zk::ProofRange,
};

use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{ballot_encrypting_tool::selection_hash, nonce::option_nonce};

/// A contest option in a pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestSelectionPreEncrypted {
    /// Label
    pub label: String,

    /// Vector of ciphertexts used to represent the selection
    pub selections: Vec<Ciphertext>,

    /// Selection hash
    pub selection_hash: HValue,
}

impl ContestSelectionPreEncrypted {
    pub fn regenerate_nonces(
        &mut self,
        device: &Device,
        primary_nonce: &[u8],
        contest_label: &String,
        selection_labels: &Vec<String>,
        j: usize,
    ) {
        for k in 0..self.selections.len() {
            self.selections[k].nonce = Some(option_nonce(
                &device.header,
                primary_nonce,
                contest_label.as_bytes(),
                selection_labels[j].as_bytes(),
                selection_labels[k].as_bytes(),
            ));
        }
    }

    pub fn new(
        header: &ElectionRecordHeader,
        primary_nonce: &[u8],
        selection: &ContestOption,
        contest_label: &String,
        selection_labels: &Vec<String>,
        j: usize,
        length: usize,
    ) -> ContestSelectionPreEncrypted {
        assert!(selection_labels.len() == length);
        let label = selection.label.clone();
        let selections = (0..length)
            .map(|k| {
                let nonce = option_nonce(
                    header,
                    primary_nonce,
                    contest_label.as_bytes(),
                    selection_labels[j].as_bytes(),
                    selection_labels[k].as_bytes(),
                );
                header.public_key.encrypt_with(
                    &header.parameters.fixed_parameters,
                    &nonce,
                    (j == k) as usize,
                    false,
                )
            })
            .collect::<Vec<Ciphertext>>();

        let selection_hash = selection_hash(&header, selections.as_ref());

        // Generate pre-encrypted votes for each possible (single) choice
        ContestSelectionPreEncrypted {
            label,
            selections,
            selection_hash,
        }
    }

    pub fn new_null(
        header: &ElectionRecordHeader,
        primary_nonce: &[u8],
        contest_label: &str,
        selection_labels: &Vec<String>,
        null_label: &str,
    ) -> ContestSelectionPreEncrypted {
        let selections = (0..selection_labels.len())
            .map(|k| {
                let nonce = option_nonce(
                    header,
                    primary_nonce,
                    contest_label.as_bytes(),
                    null_label.as_bytes(),
                    selection_labels[k].as_bytes(),
                );
                header.public_key.encrypt_with(
                    &header.parameters.fixed_parameters,
                    &nonce,
                    0,
                    false,
                )
            })
            .collect::<Vec<Ciphertext>>();

        let crypto_hash = selection_hash(header, selections.as_ref());
        // let shortcode = generate_short_code(&crypto_hash);
        ContestSelectionPreEncrypted {
            label: null_label.to_string(),
            selections,
            selection_hash: crypto_hash,
        }
    }

    pub fn proof_ballot_correctness(
        &self,
        header: &ElectionRecordHeader,
        csprng: &mut Csprng,
        sequence_order: usize,
        zmulq: Rc<ZMulPrime>,
    ) -> Vec<ProofRange> {
        let mut proofs = <Vec<ProofRange>>::new();
        for (i, selection) in self.selections.iter().enumerate() {
            proofs.push(selection.proof_ballot_correctness(
                header,
                csprng,
                sequence_order == i,
                zmulq.clone(),
            ));
        }
        proofs
    }
}
