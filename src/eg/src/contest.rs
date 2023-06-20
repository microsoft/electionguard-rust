use core::num;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    contest_hash,
    contest_selection::{ContestSelection, ContestSelectionCiphertext, ContestSelectionEncrypted},
    device::Device,
    fixed_parameters::FixedParameters,
    hash::HValue,
    nizk::ProofRange,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BallotStyle(pub String);

/// A contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contest {
    /// The label.
    pub label: String,

    /// The maximum count of options that a voter may select.
    pub selection_limit: usize,

    /// The candidates/options.
    /// The order of options matches the virtual ballot.
    pub options: Vec<ContestOption>,
}

/// An option in a contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestOption {
    /// Label
    pub label: String,
}

/// A contest in a pre-encrypted ballot.
#[derive(Debug)]
pub struct ContestEncrypted {
    /// Label
    pub label: String,

    /// Selection in this contest
    pub selection: ContestSelectionEncrypted,

    /// Contest hash
    pub crypto_hash: HValue,

    /// Proof of ballot correctness
    pub proof_ballot_correctness: Vec<ProofRange>,

    // Proof of satisfying the selection limit
    pub proof_selection_limit: ProofRange,
}

impl ContestEncrypted {
    pub fn new(
        device: &Device,
        csprng: &mut Csprng,
        primary_nonce: &[u8],
        contest: &Contest,
        pt_vote: &ContestSelection,
    ) -> ContestEncrypted {
        let selection = ContestSelectionEncrypted::new(device, primary_nonce, contest, pt_vote);
        let crypto_hash = contest_hash::encrypted(&device.config, &contest.label, &selection.vote);
        let zmulq = Rc::new(ZMulPrime::new(
            device.election_parameters.fixed_parameters.q.clone(),
        ));
        let proof_ballot_correctness = selection
            .vote
            .iter()
            .enumerate()
            .map(|(i, x)| {
                x.proof_ballot_correctness(device, csprng, pt_vote.vote[i] == 1u8, zmulq.clone())
            })
            .collect();
        let num_selections: u8 = pt_vote.vote.iter().sum();
        let proof_selection_limit = ContestEncrypted::proof_selection_limit(
            device,
            csprng,
            zmulq.clone(),
            &selection.vote,
            num_selections as usize,
            contest.selection_limit,
        );
        ContestEncrypted {
            label: contest.label.clone(),
            selection,
            crypto_hash,
            proof_ballot_correctness,
            proof_selection_limit,
        }
    }

    pub fn get_proof_ballot_correctness(&self) -> &Vec<ProofRange> {
        &self.proof_ballot_correctness
    }

    pub fn get_proof_selection_limit(&self) -> &ProofRange {
        &self.proof_selection_limit
    }

    pub fn proof_selection_limit(
        device: &Device,
        csprng: &mut Csprng,
        zmulq: Rc<ZMulPrime>,
        selection: &Vec<ContestSelectionCiphertext>,
        num_selections: usize,
        selection_limit: usize,
    ) -> ProofRange {
        let combined_selection =
            Self::sum_selection_vector(&device.election_parameters.fixed_parameters, selection);
        ProofRange::new(
            device,
            csprng,
            zmulq,
            &combined_selection.nonce,
            &combined_selection.ciphertext,
            num_selections,
            selection_limit,
        )
    }

    pub fn sum_selection_vector(
        fixed_parameters: &FixedParameters,
        selection: &Vec<ContestSelectionCiphertext>,
    ) -> ContestSelectionCiphertext {
        let mut sum_ct = selection[0].ciphertext.clone();
        let mut sum_nonce = selection[0].nonce.clone();
        for i in 1..selection.len() {
            sum_ct.alpha =
                (&sum_ct.alpha * &selection[i].ciphertext.alpha) % fixed_parameters.p.as_ref();
            sum_ct.beta =
                (&sum_ct.beta * &selection[i].ciphertext.beta) % fixed_parameters.p.as_ref();
            sum_nonce = (&sum_nonce + &selection[i].nonce) % fixed_parameters.q.as_ref();
        }

        ContestSelectionCiphertext {
            ciphertext: sum_ct,
            nonce: sum_nonce,
        }
    }
}
