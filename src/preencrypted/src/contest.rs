use std::rc::Rc;

use eg::{
    contest_encrypted::ContestEncrypted,
    contest_selection::ContestSelectionPlaintext,
    device::Device,
    election_manifest::{Contest, ContestOptionIndex},
    election_record::PreVotingData,
    fixed_parameters::FixedParameters,
    hash::HValue,
    index::GenericIndex,
    joint_election_public_key::{Ciphertext, CiphertextIndex},
    vec1::Vec1,
    zk::ProofRange,
};
use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{
    contest_hash::contest_hash,
    contest_selection::{ContestSelectionPreEncrypted, ContestSelectionPreEncryptedIndex},
};

/// A 1-based index of a [`ContestPreEncrypted`] in the order it is defined in the [`BallotPreEncrypted`].
pub type ContestPreEncryptedIndex = GenericIndex<ContestPreEncrypted>;

/// A contest in a pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestPreEncrypted {
    /// Label
    pub label: String,

    /// Selections in this contest
    pub selections: Vec1<ContestSelectionPreEncrypted>,

    /// Contest hash
    #[serde(skip)]
    pub contest_hash: HValue,
}

impl PartialEq for ContestPreEncrypted {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label && self.selections == other.selections
    }
}

impl ContestPreEncrypted {
    pub fn regenerate_nonces(
        &mut self,
        device: &Device,
        primary_nonce: &[u8],
        selection_labels: &Vec1<String>,
    ) {
        self.selections.indices().for_each(|j| {
            self.selections.get_mut(j).unwrap().regenerate_nonces(
                device,
                primary_nonce,
                &self.label,
                selection_labels,
                <GenericIndex<String>>::from_one_based_index(j.get_one_based_usize() as u32)
                    .unwrap(),
            );
        });
    }

    pub fn new(
        pvd: &PreVotingData,
        primary_nonce: &[u8],
        store_nonces: bool,
        contest: &Contest,
    ) -> ContestPreEncrypted {
        let mut selections = <Vec1<ContestSelectionPreEncrypted>>::new();
        let mut selection_labels = Vec1::new();
        contest.options.indices().for_each(|i| {
            selection_labels
                .try_push(contest.options.get(i).unwrap().label.clone())
                .unwrap();
        });
        for j in 1..contest.options.len() + 1 {
            let co_idx = ContestOptionIndex::from_one_based_index(j as u32).unwrap();
            let selection = ContestSelectionPreEncrypted::new(
                pvd,
                primary_nonce,
                store_nonces,
                &contest.options.get(co_idx).unwrap(),
                &contest.label,
                &selection_labels,
                <GenericIndex<String>>::from_one_based_index(j as u32).unwrap(),
            );
            selections.try_push(selection).unwrap();
        }

        for j in 0..contest.selection_limit {
            let selection = ContestSelectionPreEncrypted::new_null(
                pvd,
                primary_nonce,
                store_nonces,
                &contest.label,
                &selection_labels,
                &format!("null_{}", j + 1),
            );
            selections.try_push(selection).unwrap();
        }

        let contest_hash = contest_hash(pvd, &contest.label, &selections);
        ContestPreEncrypted {
            label: contest.label.clone(),
            selections,
            contest_hash: contest_hash,
        }
    }

    pub fn proof_ballot_correctness(
        &self,
        pvd: &PreVotingData,
        csprng: &mut Csprng,
        zmulq: Rc<ZMulPrime>,
    ) -> Vec1<Vec1<ProofRange>> {
        let mut proofs = Vec1::new();
        self.selections.indices().for_each(|i| {
            let selection = self.selections.get(i).unwrap();
            proofs
                .try_push(selection.proof_ballot_correctness(
                    pvd,
                    csprng,
                    i.get_one_based_usize(),
                    zmulq.clone(),
                ))
                .unwrap();
        });
        proofs
    }

    pub fn combine_voter_selections(
        &self,
        fixed_parameters: &FixedParameters,
        voter_selections: &Vec1<ContestSelectionPlaintext>,
        selection_limit: usize,
    ) -> Vec1<Ciphertext> {
        assert!(voter_selections.len() + selection_limit == self.selections.len());

        let mut selections = <Vec<&Vec1<Ciphertext>>>::new();

        voter_selections.indices().for_each(|i| {
            let v = voter_selections.get(i).unwrap();
            let i = ContestSelectionPreEncryptedIndex::from_one_based_index(
                i.get_one_based_usize() as u32,
            )
            .unwrap();
            if *v == 1 {
                selections.push(&self.selections.get(i).unwrap().selections);
            }
        });

        let mut i = self.selections.len();
        while selections.len() < selection_limit {
            let idx = ContestSelectionPreEncryptedIndex::from_one_based_index(i as u32).unwrap();
            selections.push(&self.selections.get(idx).unwrap().selections);
            i -= 1;
        }

        assert!(selections.len() == selection_limit);

        let mut combined_selection = selections[0].clone();

        for i in 1..selections.len() {
            for j in 1..combined_selection.len() + 1 {
                let j = CiphertextIndex::from_one_based_index(j as u32).unwrap();
                let combined_selection_j = combined_selection.get_mut(j).unwrap();
                let selections_i_j = selections[i].get(j).unwrap();

                combined_selection_j.alpha = (&combined_selection_j.alpha * &selections_i_j.alpha)
                    % fixed_parameters.p.as_ref();
                combined_selection_j.beta = (&combined_selection_j.beta * &selections_i_j.beta)
                    % fixed_parameters.p.as_ref();
                combined_selection_j.nonce = Some(
                    (combined_selection_j.nonce.as_ref().unwrap()
                        + selections_i_j.nonce.as_ref().unwrap())
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
        voter_selections: &Vec1<u8>,
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

        let mut proof_ballot_correctness = Vec1::new();
        selection.indices().for_each(|i| {
            proof_ballot_correctness
                .try_push(
                    selection.get(i).unwrap().proof_ballot_correctness(
                        &device.header,
                        csprng,
                        *voter_selections
                            .get(
                                <GenericIndex<u8>>::from_one_based_index(
                                    i.get_one_based_usize() as u32
                                )
                                .unwrap(),
                            )
                            .unwrap()
                            == 1u8,
                        zmulq.clone(),
                    ),
                )
                .unwrap();
        });
        // let num_selections: u8 = voter_selections.iter().sum();

        let mut num_selections = 0;
        voter_selections
            .indices()
            .for_each(|i| num_selections += voter_selections.get(i).unwrap());

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
