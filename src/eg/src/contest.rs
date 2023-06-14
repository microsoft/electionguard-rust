use std::{borrow::Borrow, rc::Rc};

use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, z_mul_prime::ZMulPrime};

use crate::{
    ballot::BallotConfig,
    ballot_encrypting_tool::BallotEncryptingTool,
    contest_hash::ContestHash,
    contest_selection::{
        ContestSelectionCiphertext, ContestSelectionEncrypted, ContestSelectionPlaintext,
        ContestSelectionPreEncrypted,
    },
    fixed_parameters::FixedParameters,
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

    /// Ballot style
    pub ballot_style: BallotStyle,
}

/// An option in a contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestOption {
    /// Label
    pub label: String,
}

/// A contest in a pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContestPreEncrypted {
    /// Label
    pub label: String,

    /// Selections in this contest
    pub selections: Vec<ContestSelectionPreEncrypted>,

    /// Contest hash
    pub crypto_hash: String,

    /// Ballot style
    pub ballot_style: BallotStyle,
}

/// A contest in a pre-encrypted ballot.
#[derive(Debug)]
pub struct ContestEncrypted {
    /// Label
    pub label: String,

    /// Selection in this contest
    pub selection: ContestSelectionEncrypted,

    /// Contest hash
    pub crypto_hash: String,

    /// Ballot style
    pub ballot_style: BallotStyle,

    /// Proof of ballot correctness
    pub proof_ballot_correctness: Vec<ProofRange>,

    // Proof of satisfying the selection limit
    pub proof_selection_limit: ProofRange,
}

impl ContestPreEncrypted {
    pub fn get_label(&self) -> &String {
        &self.label
    }

    pub fn get_selections(&self) -> &Vec<ContestSelectionPreEncrypted> {
        &self.selections
    }

    pub fn get_crypto_hash(&self) -> &String {
        &self.crypto_hash
    }

    pub fn regenerate_nonces(
        &mut self,
        config: &BallotConfig,
        fixed_parameters: &FixedParameters,
        primary_nonce: &[u8],
        selection_labels: &Vec<String>,
    ) {
        for j in 0..self.selections.len() {
            self.selections[j].regenerate_nonces(
                config,
                fixed_parameters,
                primary_nonce,
                &self.label,
                &selection_labels,
                j,
            );
        }
    }

    pub fn try_new(
        config: &BallotConfig,
        primary_nonce: &[u8],
        contest: &Contest,
        fixed_parameters: &FixedParameters,
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
                config,
                primary_nonce,
                &contest.options[j],
                contest.label.borrow(),
                selection_labels.borrow(),
                j,
                selection_labels.len(),
                fixed_parameters,
            );
            success &= BallotEncryptingTool::check_shortcode(&selections, &selection);
            if success {
                selections.push(selection);
            }
        }

        // generate_selection also generates encrypted null selections

        match success {
            true => {
                let crypto_hash = ContestHash::pre_encrypted(config, &contest.label, &selections);

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
        csprng: &mut Csprng,
        fixed_parameters: &FixedParameters,
        config: &BallotConfig,
        zmulq: Rc<ZMulPrime>,
    ) -> Vec<Vec<ProofRange>> {
        let mut proofs = <Vec<Vec<ProofRange>>>::new();
        for (i, selection) in self.selections.iter().enumerate() {
            proofs.push(selection.proof_ballot_correctness(
                csprng,
                fixed_parameters,
                config,
                i,
                zmulq.clone(),
            ));
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
}

impl ContestEncrypted {
    pub fn new_from_preencrypted(
        config: &BallotConfig,
        fixed_parameters: &FixedParameters,
        csprng: &mut Csprng,
        pre_encrypted: &ContestPreEncrypted,
        voter_selections: &Vec<ContestSelectionPlaintext>,
        selection_limit: usize,
    ) -> Self {
        let zmulq = Rc::new(ZMulPrime::new(fixed_parameters.q.clone()));

        let selection = ContestSelectionEncrypted {
            vote: pre_encrypted.combine_voter_selections(fixed_parameters, voter_selections),
            crypto_hash: pre_encrypted.get_crypto_hash().clone(),
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
                x.proof_ballot_correctness(
                    csprng,
                    fixed_parameters,
                    config,
                    selected_vec[i],
                    zmulq.clone(),
                )
            })
            .collect();
        let proof_selection_limit = Self::proof_selection_limit(
            csprng,
            fixed_parameters,
            config,
            zmulq.clone(),
            &selection.vote,
            voter_selections.len(),
            selection_limit,
        );

        // TODO: Change crypto hash
        ContestEncrypted {
            ballot_style: pre_encrypted.ballot_style.clone(),
            label: pre_encrypted.label.clone(),
            selection,
            crypto_hash: pre_encrypted.get_crypto_hash().clone(),
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

    fn proof_selection_limit(
        csprng: &mut Csprng,
        fixed_parameters: &FixedParameters,
        config: &BallotConfig,
        zmulq: Rc<ZMulPrime>,
        selection: &Vec<ContestSelectionCiphertext>,
        num_selections: usize,
        selection_limit: usize,
    ) -> ProofRange {
        let combined_selection = Self::sum_selection_vector(fixed_parameters, selection);
        ProofRange::new(
            csprng,
            fixed_parameters,
            config,
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
