use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use qrcode::{render::svg, QrCode};
use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

use crate::{
    confirmation_code::ConfirmationCode,
    contest::{ContestEncrypted, ContestPreEncrypted},
    contest_selection::{ContestSelection, ContestSelectionEncrypted},
    device::Device,
    election_manifest::ElectionManifest,
    fixed_parameters::FixedParameters,
    hash::HValue,
    key::PublicKey,
    voter::VoterVerificationCode,
};

/// A pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct BallotPreEncrypted {
    /// Label
    pub label: String,

    /// Contests in this ballot
    pub contests: Vec<ContestPreEncrypted>,

    /// Confirmation code
    pub confirmation_code: ConfirmationCode,
}

/// An encrypted ballot.
#[derive(Debug)]
pub struct BallotEncrypted {
    /// Label
    pub label: String,

    /// Contests in this ballot
    pub contests: Vec<ContestEncrypted>,

    /// Confirmation code
    pub confirmation_code: ConfirmationCode,

    /// Date (and time) of ballot generation
    pub date: String,

    /// Device that generated this ballot
    pub device: String,
}

/// A decrypted ballot.
#[derive(Debug)]
pub struct BallotDecrypted {
    /// Label
    pub label: String,

    /// Encrypted selections made by the voter
    pub encrypted_selections: Vec<ContestSelectionEncrypted>,

    /// Decrypted selections made by the voter
    pub decrypted_selections: Vec<ContestSelection>,

    /// Confirmation code
    pub confirmation_code: ConfirmationCode,
}

/// Configuration for generating encrypted ballots.
#[derive(Clone)]
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

impl BallotDecrypted {
    pub fn new_pick_random(config: &BallotConfig, csprng: &mut Csprng, label: String) -> Self {
        let mut contests = Vec::new();
        for contest in &config.manifest.contests {
            contests.push(ContestSelection::new_pick_random(
                csprng,
                contest.selection_limit,
                contest.options.len(),
            ));
        }
        Self {
            label,
            decrypted_selections: contests,
            encrypted_selections: Vec::new(),
            confirmation_code: ConfirmationCode("".to_string()),
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

    pub fn get_confirmation_code(&self) -> &ConfirmationCode {
        &self.confirmation_code
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
                    confirmation_code: crypto_hash,
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
        device: &Device,
        csprng: &mut Csprng,
        pre_encrypted: &BallotPreEncrypted,
        voter_ballot: &BallotDecrypted,
    ) -> Self {
        let contests = (0..pre_encrypted.contests.len())
            .map(|i| {
                ContestEncrypted::new_from_preencrypted(
                    &device.config,
                    &device.election_parameters.fixed_parameters,
                    csprng,
                    &pre_encrypted.contests[i],
                    &voter_ballot.decrypted_selections[i].vote,
                    device.config.manifest.contests[i].selection_limit,
                )
            })
            .collect::<Vec<ContestEncrypted>>();

        BallotEncrypted {
            date: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string(),
            device: device.get_uuid().clone(),
            label: pre_encrypted.get_label().clone(),
            contests,
            confirmation_code: pre_encrypted.get_confirmation_code().clone(),
        }
    }

    pub fn instant_verification_code(&self, primary_nonce: &String, dir_path: &Path) {
        let code = QrCode::new(
            serde_json::to_string(&VoterVerificationCode {
                pn: primary_nonce.clone(),
                cc: self.confirmation_code.0.clone(),
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
