use std::rc::Rc;

use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{
    contest_hash, contest_selection::ContestSelection, device::Device,
    election_record::PreVotingData, fixed_parameters::FixedParameters, hash::HValue,
    joint_election_public_key::Ciphertext, nonce::encrypted as nonce, zk::ProofRange,
};

/// A contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contest {
    /// The label.
    pub label: String,

    /// The maximum count of options that a voter may select.
    pub selection_limit: usize,

    /// The candidates/options. The order of options matches the virtual ballot.
    pub options: Vec<ContestOption>,
}

/// An option in a contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestOption {
    /// The label.
    pub label: String,
}

/// A contest in an encrypted ballot.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContestEncrypted {
    /// The label.
    pub label: String,

    /// Encrypted voter selection vector.
    pub selection: Vec<Ciphertext>,

    /// Contest hash.
    pub contest_hash: HValue,

    /// Proof of ballot correctness.
    pub proof_ballot_correctness: Vec<ProofRange>,

    // Proof of satisfying the selection limit.
    pub proof_selection_limit: ProofRange,
}

impl ContestEncrypted {
    fn encrypt_selection(
        header: &PreVotingData,
        primary_nonce: &[u8],
        contest: &Contest,
        pt_vote: &ContestSelection,
    ) -> Vec<Ciphertext> {
        // TODO: Check if selection limit is satisfied

        let mut vote: Vec<Ciphertext> = Vec::new();
        for (j, v) in pt_vote.vote.iter().enumerate() {
            let nonce = nonce(
                header,
                primary_nonce,
                contest.label.as_bytes(),
                contest.options[j].label.as_bytes(),
            );
            vote.push(header.public_key.encrypt_with(
                &header.parameters.fixed_parameters,
                &nonce,
                *v as usize,
                true,
            ));
        }
        vote
    }

    pub fn new(
        device: &Device,
        csprng: &mut Csprng,
        primary_nonce: &[u8],
        contest: &Contest,
        pt_vote: &ContestSelection,
    ) -> ContestEncrypted {
        let selection = Self::encrypt_selection(&device.header, primary_nonce, contest, pt_vote);
        let contest_hash = contest_hash::contest_hash(&device.header, &contest.label, &selection);
        let zmulq = Rc::new(ZMulPrime::new(
            device.header.parameters.fixed_parameters.q.clone(),
        ));
        let proof_ballot_correctness = selection
            .iter()
            .enumerate()
            .map(|(i, x)| {
                x.proof_ballot_correctness(
                    &device.header,
                    csprng,
                    pt_vote.vote[i] == 1u8,
                    zmulq.clone(),
                )
            })
            .collect();
        let num_selections: u8 = pt_vote.vote.iter().sum();
        let proof_selection_limit = ContestEncrypted::proof_selection_limit(
            &device.header,
            csprng,
            zmulq.clone(),
            &selection,
            num_selections as usize,
            contest.selection_limit,
        );
        ContestEncrypted {
            label: contest.label.clone(),
            selection,
            contest_hash,
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
        header: &PreVotingData,
        csprng: &mut Csprng,
        zmulq: Rc<ZMulPrime>,
        selection: &Vec<Ciphertext>,
        num_selections: usize,
        selection_limit: usize,
    ) -> ProofRange {
        let combined_ct =
            Self::sum_selection_vector(&header.parameters.fixed_parameters, selection);
        ProofRange::new(
            header,
            csprng,
            zmulq,
            &combined_ct,
            num_selections,
            selection_limit,
        )
    }

    pub fn sum_selection_vector(
        fixed_parameters: &FixedParameters,
        selection: &Vec<Ciphertext>,
    ) -> Ciphertext {
        let mut sum_ct = selection[0].clone();
        assert!(sum_ct.nonce.is_some());
        let mut sum_nonce = selection[0].nonce.as_ref().unwrap().clone();

        for i in 1..selection.len() {
            sum_ct.alpha = (&sum_ct.alpha * &selection[i].alpha) % fixed_parameters.p.as_ref();
            sum_ct.beta = (&sum_ct.beta * &selection[i].beta) % fixed_parameters.p.as_ref();

            sum_nonce =
                (sum_nonce + selection[i].nonce.as_ref().unwrap()) % fixed_parameters.q.as_ref();
        }

        sum_ct.nonce = Some(sum_nonce);
        sum_ct
    }
}
