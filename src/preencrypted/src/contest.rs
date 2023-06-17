use std::rc::Rc;

use eg::{
    ballot::BallotConfig,
    contest::{BallotStyle, Contest, ContestEncrypted},
    contest_selection::{
        ContestSelectionCiphertext, ContestSelectionEncrypted, ContestSelectionPlaintext,
    },
    device::Device,
    fixed_parameters::FixedParameters,
    hash::HValue,
    nizk::ProofRange,
};
use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{
    ballot_encrypting_tool::check_shortcode, contest_hash::contest_hash,
    contest_selection::ContestSelectionPreEncrypted,
};

/// A contest in a pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestPreEncrypted {
    /// Label
    pub label: String,

    /// Selections in this contest
    pub selections: Vec<ContestSelectionPreEncrypted>,

    /// Contest hash
    pub crypto_hash: HValue,

    /// Ballot style
    pub ballot_style: BallotStyle,
}

impl ContestPreEncrypted {
    pub fn get_label(&self) -> &String {
        &self.label
    }

    pub fn get_selections(&self) -> &Vec<ContestSelectionPreEncrypted> {
        &self.selections
    }

    pub fn get_crypto_hash(&self) -> &HValue {
        &self.crypto_hash
    }

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

    pub fn try_new(
        device: &Device,
        primary_nonce: &[u8],
        contest: &Contest,
    ) -> Option<ContestPreEncrypted> {
        let mut success = true;
        let mut selections = <Vec<ContestSelectionPreEncrypted>>::new();
        let selection_labels = contest
            .options
            .iter()
            .map(|o| o.label.clone())
            .collect::<Vec<String>>();
        for j in 0..contest.options.len() {
            let selection = ContestSelectionPreEncrypted::new(
                device,
                primary_nonce,
                &contest.options[j],
                &contest.label,
                &selection_labels,
                j,
                selection_labels.len(),
            );
            success &= check_shortcode(&selections, &selection);
            if success {
                selections.push(selection);
            }
        }

        // generate_selection also generates encrypted null selections

        match success {
            true => {
                let crypto_hash = contest_hash(&device.config, &contest.label, &selections);

                Some(ContestPreEncrypted {
                    label: contest.label.clone(),
                    selections,
                    crypto_hash,
                    ballot_style: contest.ballot_style.clone(),
                })
            }
            false => None,
        }
    }

    pub fn proof_ballot_correctness(
        &self,
        device: &Device,
        csprng: &mut Csprng,
        zmulq: Rc<ZMulPrime>,
    ) -> Vec<Vec<ProofRange>> {
        let mut proofs = <Vec<Vec<ProofRange>>>::new();
        for (i, selection) in self.selections.iter().enumerate() {
            proofs.push(selection.proof_ballot_correctness(device, csprng, i, zmulq.clone()));
        }
        proofs
    }

    pub fn combine_voter_selections(
        &self,
        fixed_parameters: &FixedParameters,
        voter_selections: &[ContestSelectionPlaintext],
    ) -> Vec<ContestSelectionCiphertext> {
        assert!(0 < voter_selections.len() && voter_selections.len() <= self.selections.len());

        let mut selections = <Vec<&Vec<ContestSelectionCiphertext>>>::new();
        for idx in voter_selections {
            selections.push(&self.selections[*idx as usize].selections);
        }

        let mut combined_selection = selections[0].clone();

        for i in 1..voter_selections.len() {
            for j in 0..combined_selection.len() {
                combined_selection[j].ciphertext.alpha = (&combined_selection[j].ciphertext.alpha
                    * &selections[i][j].ciphertext.alpha)
                    % fixed_parameters.p.as_ref();
                combined_selection[j].ciphertext.beta = (&combined_selection[j].ciphertext.beta
                    * &selections[i][j].ciphertext.beta)
                    % fixed_parameters.p.as_ref();
                combined_selection[j].nonce = (&combined_selection[j].nonce
                    + &selections[i][j].nonce)
                    % fixed_parameters.q.as_ref();
            }
        }
        combined_selection
    }

    pub fn finalize(
        &self,
        device: &Device,
        csprng: &mut Csprng,
        voter_selections: &Vec<ContestSelectionPlaintext>,
        selection_limit: usize,
    ) -> ContestEncrypted {
        let zmulq = Rc::new(ZMulPrime::new(
            device.election_parameters.fixed_parameters.q.clone(),
        ));

        let selection = ContestSelectionEncrypted {
            vote: self.combine_voter_selections(
                &device.election_parameters.fixed_parameters,
                voter_selections,
            ),
            crypto_hash: self.crypto_hash,
        };

        let mut selected_vec = (0..selection.vote.len())
            .map(|_| false)
            .collect::<Vec<bool>>();
        for v in voter_selections {
            selected_vec[*v as usize] = true;
        }
        let proof_ballot_correctness = selection
            .vote
            .iter()
            .enumerate()
            .map(|(i, x)| {
                x.proof_ballot_correctness(device, csprng, selected_vec[i], zmulq.clone())
            })
            .collect();
        let proof_selection_limit = ContestEncrypted::proof_selection_limit(
            device,
            csprng,
            zmulq.clone(),
            &selection.vote,
            voter_selections.len(),
            selection_limit,
        );

        // TODO: Change crypto hash
        ContestEncrypted {
            ballot_style: self.ballot_style.clone(),
            label: self.label.clone(),
            selection,
            crypto_hash: self.crypto_hash,
            proof_ballot_correctness,
            proof_selection_limit,
        }
    }
}
