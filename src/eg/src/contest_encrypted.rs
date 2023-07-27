use std::rc::Rc;

use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{
    contest_hash,
    contest_selection::ContestSelection,
    device::Device,
    election_manifest::{Contest, ContestOptionIndex},
    election_record::PreVotingData,
    fixed_parameters::FixedParameters,
    hash::HValue,
    index::Index,
    joint_election_public_key::Ciphertext,
    nonce::encrypted as nonce,
    vec1::Vec1,
    zk::ProofRange,
};

// /// A contest.
// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct Contest {
//     /// The label.
//     pub label: String,

//     /// The maximum count of options that a voter may select.
//     pub selection_limit: usize,

//     /// The candidates/options. The order of options matches the virtual ballot.
//     pub options: Vec<ContestOption>,
// }

// /// An option in a contest.
// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct ContestOption {
//     /// The label.
//     pub label: String,
// }

/// A 1-based index of a [`ContestEncrypted`] in the order it is defined in the [`BallotEncrypted`].
pub type ContestEncryptedIndex = Index<ContestEncrypted>;

/// A contest in an encrypted ballot.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContestEncrypted {
    /// Encrypted voter selection vector.
    pub selection: Vec<Ciphertext>,

    /// Contest hash.
    pub contest_hash: HValue,

    /// Proof of ballot correctness.
    pub proof_ballot_correctness: Vec1<ProofRange>,

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
        for j in 1..pt_vote.vote.len() + 1 {
            let o_idx = ContestOptionIndex::from_one_based_index(j as u32).unwrap();
            let nonce = nonce(
                header,
                primary_nonce,
                contest.label.as_bytes(),
                contest.options.get(o_idx).unwrap().label.as_bytes(),
            );
            vote.push(header.public_key.encrypt_with(
                &header.parameters.fixed_parameters,
                &nonce,
                pt_vote.vote[j] as usize,
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
        let mut proof_ballot_correctness = Vec1::new();
        for i in 0..selection.len() {
            proof_ballot_correctness
                .try_push(selection[i].proof_ballot_correctness(
                    &device.header,
                    csprng,
                    pt_vote.vote[i] == 1u8,
                    zmulq.clone(),
                ))
                .unwrap();
        }

        // selection.indices().for_each(|i| {
        //     let v_idx = ContestSelectionPlaintextIndex::from_one_based_index(
        //         i.get_zero_based_usize() as u32,
        //     )
        //     .unwrap();
        //     selection.get(i).unwrap().proof_ballot_correctness(
        //         &device.header,
        //         csprng,
        //         *pt_vote.vote.get(v_idx).unwrap() == 1u8,
        //         zmulq.clone(),
        //     )
        // });

        let mut num_selections = 0;
        pt_vote.vote.iter().for_each(|v| num_selections += v);

        let proof_selection_limit = ContestEncrypted::proof_selection_limit(
            &device.header,
            csprng,
            zmulq.clone(),
            &selection,
            num_selections as usize,
            contest.selection_limit,
        );
        ContestEncrypted {
            selection,
            contest_hash,
            proof_ballot_correctness,
            proof_selection_limit,
        }
    }

    pub fn get_proof_ballot_correctness(&self) -> &Vec1<ProofRange> {
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
        // let mut sum_ct = selection[0].clone();
        let mut sum_ct = selection[0].clone();
        assert!(sum_ct.nonce.is_some());
        let mut sum_nonce = sum_ct.nonce.as_ref().unwrap().clone();

        for i in 1..selection.len() {
            let selection_i = &selection[i];

            sum_ct.alpha = (&sum_ct.alpha * &selection_i.alpha) % fixed_parameters.p.as_ref();
            sum_ct.beta = (&sum_ct.beta * &selection_i.beta) % fixed_parameters.p.as_ref();

            sum_nonce =
                (sum_nonce + selection_i.nonce.as_ref().unwrap()) % fixed_parameters.q.as_ref();
        }

        sum_ct.nonce = Some(sum_nonce);
        sum_ct
    }
}
