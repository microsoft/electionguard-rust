use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use qrcode::{render::svg, QrCode};
use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

use crate::{
    ballot_encrypting_tool::BallotEncryptingTool,
    confirmation_code::ConfirmationCode,
    contest::{ContestEncrypted, ContestPreEncrypted},
    election_manifest::ElectionManifest,
    fixed_parameters::FixedParameters,
    hash::HValue,
    key::PublicKey,
};

#[derive(Debug, Serialize)]
pub struct VoterContest {
    /// Label
    pub label: String,

    /// Selection
    pub selection: Vec<usize>,
}

#[derive(Debug, Serialize)]
pub struct VoterBallot {
    /// Label
    pub label: String,

    /// Contests in this ballot
    pub contests: Vec<VoterContest>,
}

#[derive(Debug, Serialize)]
pub struct InstantVerificationCode {
    pub pn: String,
    pub cc: String,
}

/// A pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct BallotPreEncrypted {
    /// Label
    pub label: String,

    /// Contests in this ballot
    pub contests: Vec<ContestPreEncrypted>,

    /// Confirmation code
    pub crypto_hash: String,
}

/// An encrypted ballot.
#[derive(Debug)]
pub struct BallotEncrypted {
    /// Label
    pub label: String,

    /// Contests in this ballot
    pub contests: Vec<ContestEncrypted>,

    /// Confirmation code
    pub crypto_hash: String,
}

/// Configuration for generating encrypted ballots.
pub struct BallotConfig {
    /// Election manifest
    pub manifest: ElectionManifest,
    // ballot_style: BallotStyle,
    /// Election public key
    pub election_public_key: PublicKey,

    /// Whether to encrypt the nonce with the election public key
    // pub encrypt_nonce: bool,

    /// Election extended base hash
    pub h_e: HValue,
}

impl VoterBallot {
    pub fn new_pick_random(config: &BallotConfig, csprng: &mut Csprng, label: String) -> Self {
        let mut contests = Vec::new();
        for contest in &config.manifest.contests {
            contests.push(VoterContest::new_pick_random(
                csprng,
                contest.label.clone(),
                contest.selection_limit,
                contest.options.len(),
            ));
        }
        Self { label, contests }
    }
}

impl VoterContest {
    pub fn new_pick_random(
        csprng: &mut Csprng,
        label: String,
        selection_limit: usize,
        num_options: usize,
    ) -> Self {
        let mut selection = HashSet::new();
        // TODO: Allow 0 selections
        let selection_limit = 1 + (csprng.next_u64() as usize % selection_limit);

        while selection.len() < selection_limit {
            selection.insert(csprng.next_u64() as usize % num_options);
        }

        Self {
            label,
            selection: selection.into_iter().collect(),
        }
    }
}

impl BallotPreEncrypted {
    pub fn get_label(&self) -> &String {
        &self.label
    }

    pub fn get_contests(&self) -> &Vec<ContestPreEncrypted> {
        &self.contests
    }

    pub fn get_crypto_hash(&self) -> &String {
        &self.crypto_hash
    }

    pub fn try_new_with(
        config: &BallotConfig,
        fixed_parameters: &FixedParameters,
        primary_nonce: &[u8],
    ) -> Option<Self> {
        // TODO: Find contests in manifest corresponding to requested ballot style

        // Generate contests

        // println!("Primary nonce = {:?}", primary_nonce);

        let label = "Sample Election".to_string();
        let b_aux = "Sample Aux Info".as_bytes();

        let mut success = true;
        let mut contests = Vec::new();
        for contest in &config.manifest.contests {
            match ContestPreEncrypted::try_new(
                config,
                primary_nonce.as_ref(),
                &contest,
                fixed_parameters,
            ) {
                Some(c) => contests.push(c),
                None => {
                    success = false;
                    break;
                }
            }
        }

        match success {
            true => {
                let crypto_hash = ConfirmationCode::pre_encrypted(config, &contests, b_aux);

                println!("Confirmation Code:\t{:?}", crypto_hash);

                Some(BallotPreEncrypted {
                    label,
                    contests,
                    crypto_hash,
                })
            }
            false => None,
        }
    }

    pub fn new(
        config: &BallotConfig,
        fixed_parameters: &FixedParameters,
        csprng: &mut Csprng,
    ) -> (BallotPreEncrypted, String) {
        loop {
            // Generate primary nonce
            let mut primary_nonce = [0u8; 32];
            (0..32).for_each(|i| primary_nonce[i] = csprng.next_u8());

            println!("Primary nonce = {:?}", primary_nonce);
            match BallotPreEncrypted::try_new_with(config, fixed_parameters, &primary_nonce) {
                Some(ballot) => return (ballot, HValue(primary_nonce).to_string()),
                None => continue,
            }
        }
    }

    // pub fn nizkp(
    //     &self,
    //     csprng: &mut Csprng,
    //     fixed_parameters: &FixedParameters,
    //     config: &EncryptedBallotConfig,
    //     voter_selections: &Vec<Vec<usize>>,
    // ) -> (Vec<Vec<Vec<ProofRange>>>, Vec<ProofRange>) {
    //     assert!(voter_selections.len() == self.contests.len());

    //     // let zmulp = Rc::new(ZMulPrime::new(fixed_parameters.p.clone()));
    //     let zmulq = Rc::new(ZMulPrime::new(fixed_parameters.q.clone()));

    //     let mut proof_ballot_correctness = <Vec<Vec<Vec<ProofRange>>>>::new();
    //     let mut proof_selection_limit = <Vec<ProofRange>>::new();
    //     for (i, contest) in self.contests.iter().enumerate() {
    //         proof_ballot_correctness.push(contest.proof_ballot_correctness(
    //             csprng,
    //             fixed_parameters,
    //             config,
    //             zmulq.clone(),
    //         ));
    //         proof_selection_limit.push(contest.proof_selection_limit(
    //             csprng,
    //             fixed_parameters,
    //             config,
    //             zmulq.clone(),
    //             config.manifest.contests[i].selection_limit,
    //             voter_selections[i].as_slice(),
    //         ));
    //     }

    //     (proof_ballot_correctness, proof_selection_limit)
    // }

    pub fn try_new_from_file(path: &PathBuf) -> Option<Self> {
        match fs::read_to_string(path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(ballot) => Some(ballot),
                Err(e) => {
                    println!("Error: {:?}", e);
                    None
                }
            },
            Err(e) => {
                println!("Error: {:?}", e);
                None
            }
        }
    }
}

impl BallotEncrypted {
    pub fn new_from_preencrypted(
        config: &BallotConfig,
        fixed_parameters: &FixedParameters,
        csprng: &mut Csprng,
        pre_encrypted: &BallotPreEncrypted,
        voter_ballot: &VoterBallot,
    ) -> Self {
        let contests = (0..pre_encrypted.contests.len())
            .map(|i| {
                ContestEncrypted::new_from_preencrypted(
                    config,
                    fixed_parameters,
                    csprng,
                    &pre_encrypted.contests[i],
                    &voter_ballot.contests[i].selection,
                    config.manifest.contests[i].selection_limit,
                )
            })
            .collect::<Vec<ContestEncrypted>>();

        BallotEncrypted {
            label: pre_encrypted.get_label().clone(),
            contests,
            crypto_hash: pre_encrypted.get_crypto_hash().clone(),
        }
    }

    pub fn instant_verification_code(&self, primary_nonce: &String, dir_path: &Path) {
        let code = QrCode::new(
            serde_json::to_string(&InstantVerificationCode {
                pn: primary_nonce.clone(),
                cc: self.crypto_hash.clone(),
            })
            .unwrap()
            .as_bytes(),
        )
        .unwrap();
        let image = code
            .render()
            .min_dimensions(200, 200)
            .dark_color(svg::Color("#800000"))
            .light_color(svg::Color("#ffff80"))
            .build();
        fs::write(dir_path.join(format!("{}.svg", primary_nonce)), image).unwrap();
        // println!("{}", image);
    }
}
