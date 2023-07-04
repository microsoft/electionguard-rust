use std::rc::Rc;

use eg::{
    contest::{Contest, ContestEncrypted},
    device::Device,
    election_record::ElectionRecordHeader,
    fixed_parameters::FixedParameters,
    hash::HValue,
    joint_election_public_key::Ciphertext,
    zk::ProofRange,
};
use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{contest_hash::contest_hash, contest_selection::ContestSelectionPreEncrypted};

/// A contest in a pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestPreEncrypted {
    /// Label
    pub label: String,

    /// Selections in this contest
    pub selections: Vec<ContestSelectionPreEncrypted>,

    /// Contest hash
    pub contest_hash: HValue,
}

impl PartialEq for ContestPreEncrypted {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label
            && self.contest_hash == other.contest_hash
            && self.selections.as_slice() == other.selections.as_slice()
    }
}

impl ContestPreEncrypted {
    pub fn regenerate_nonces(
        &mut self,
        device: &Device,
        primary_nonce: &[u8],
        selection_labels: &Vec<String>,
    ) {
        for j in 0..self.selections.len() {
            self.selections[j].regenerate_nonces(
                device,
                primary_nonce,
                &self.label,
                &selection_labels,
                j,
            );
        }
    }

    pub fn new(
        header: &ElectionRecordHeader,
        primary_nonce: &[u8],
        store_nonces: bool,
        contest: &Contest,
    ) -> ContestPreEncrypted {
        let mut selections = <Vec<ContestSelectionPreEncrypted>>::new();
        let selection_labels = contest
            .options
            .iter()
            .map(|o| o.label.clone())
            .collect::<Vec<String>>();
        for j in 0..contest.options.len() {
            let selection = ContestSelectionPreEncrypted::new(
                header,
                primary_nonce,
                store_nonces,
                &contest.options[j],
                &contest.label,
                &selection_labels,
                j,
                selection_labels.len(),
            );
            selections.push(selection);
        }

        for j in 0..contest.selection_limit {
            let selection = ContestSelectionPreEncrypted::new_null(
                header,
                primary_nonce,
                store_nonces,
                &contest.label,
                &selection_labels,
                &format!("null_{}", j + 1),
            );
            selections.push(selection);
        }

        let contest_hash = contest_hash(header, &contest.label, &selections);
        ContestPreEncrypted {
            label: contest.label.clone(),
            selections,
            contest_hash,
        }
    }

    pub fn proof_ballot_correctness(
        &self,
        header: &ElectionRecordHeader,
        csprng: &mut Csprng,
        zmulq: Rc<ZMulPrime>,
    ) -> Vec<Vec<ProofRange>> {
        let mut proofs = <Vec<Vec<ProofRange>>>::new();
        for (i, selection) in self.selections.iter().enumerate() {
            proofs.push(selection.proof_ballot_correctness(header, csprng, i, zmulq.clone()));
        }
        proofs
    }

    pub fn combine_voter_selections(
        &self,
        fixed_parameters: &FixedParameters,
        voter_selections: &[u8],
        selection_limit: usize,
    ) -> Vec<Ciphertext> {
        assert!(voter_selections.len() + selection_limit == self.selections.len());

        let mut selections = <Vec<&Vec<Ciphertext>>>::new();

        for (i, v) in voter_selections.iter().enumerate() {
            if *v == 1 {
                selections.push(&self.selections[i].selections);
            }
        }

        let mut i = self.selections.len() - 1;
        while selections.len() < selection_limit {
            selections.push(&self.selections[i].selections);
            i -= 1;
        }

        assert!(selections.len() == selection_limit);

        let mut combined_selection = selections[0].clone();

        for i in 1..selections.len() {
            for j in 0..combined_selection.len() {
                combined_selection[j].alpha = (&combined_selection[j].alpha
                    * &selections[i][j].alpha)
                    % fixed_parameters.p.as_ref();
                combined_selection[j].beta = (&combined_selection[j].beta * &selections[i][j].beta)
                    % fixed_parameters.p.as_ref();
                combined_selection[j].nonce = Some(
                    (combined_selection[j].nonce.as_ref().unwrap()
                        + selections[i][j].nonce.as_ref().unwrap())
                        % fixed_parameters.q.as_ref(),
                );
            }
        }
        combined_selection
    }

    pub fn finalize(
        &self,
        device: &Device,
        csprng: &mut Csprng,
        voter_selections: &Vec<u8>,
        selection_limit: usize,
    ) -> ContestEncrypted {
        let zmulq = Rc::new(ZMulPrime::new(
            device.header.parameters.fixed_parameters.q.clone(),
        ));

        let selection = self.combine_voter_selections(
            &device.header.parameters.fixed_parameters,
            voter_selections,
            selection_limit,
        );

        let proof_ballot_correctness = selection
            .iter()
            .enumerate()
            .map(|(i, x)| {
                x.proof_ballot_correctness(
                    &device.header,
                    csprng,
                    voter_selections[i] == 1,
                    zmulq.clone(),
                )
            })
            .collect();
        let num_selections: u8 = voter_selections.iter().sum();
        let proof_selection_limit = ContestEncrypted::proof_selection_limit(
            &device.header,
            csprng,
            zmulq.clone(),
            &selection,
            num_selections as usize,
            selection_limit,
        );

        // TODO: Change crypto hash
        ContestEncrypted {
            label: self.label.clone(),
            selection,
            contest_hash: self.contest_hash,
            proof_ballot_correctness,
            proof_selection_limit,
        }
    }
}
