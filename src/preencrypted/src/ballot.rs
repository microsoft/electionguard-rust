use std::{fs, path::PathBuf, time::SystemTime};

use eg::{
    ballot::{BallotDecrypted, BallotEncrypted},
    contest::ContestEncrypted,
    device::Device,
    hash::HValue,
};
use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, logging::Logging};

use crate::{confirmation_code::confirmation_code, contest::ContestPreEncrypted};

/// A pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct BallotPreEncrypted {
    /// Label
    pub label: String,

    /// Contests in this ballot
    pub contests: Vec<ContestPreEncrypted>,

    /// Confirmation code
    pub confirmation_code: HValue,
}

impl BallotPreEncrypted {
    pub fn get_label(&self) -> &String {
        &self.label
    }

    pub fn get_contests(&self) -> &Vec<ContestPreEncrypted> {
        &self.contests
    }

    pub fn get_confirmation_code(&self) -> &HValue {
        &self.confirmation_code
    }

    pub fn try_new_with(device: &Device, primary_nonce: &[u8]) -> Option<Self> {
        // TODO: Find contests in manifest corresponding to requested ballot style

        // Generate contests

        let label = "Sample Election".to_string();
        let b_aux = "Sample Aux Info".as_bytes();

        let mut success = true;
        let mut contests = Vec::new();
        for contest in &device.config.manifest.contests {
            match ContestPreEncrypted::try_new(device, primary_nonce.as_ref(), &contest) {
                Some(c) => contests.push(c),
                None => {
                    success = false;
                    break;
                }
            }
        }

        match success {
            true => {
                let crypto_hash = confirmation_code(&device.config, &contests, b_aux);

                Some(BallotPreEncrypted {
                    label,
                    contests,
                    confirmation_code: crypto_hash,
                })
            }
            false => None,
        }
    }

    pub fn new(device: &Device, csprng: &mut Csprng) -> (BallotPreEncrypted, HValue) {
        loop {
            // Generate primary nonce
            let mut primary_nonce = [0u8; 32];
            (0..32).for_each(|i| primary_nonce[i] = csprng.next_u8());

            match BallotPreEncrypted::try_new_with(device, &primary_nonce) {
                Some(ballot) => return (ballot, HValue(primary_nonce)),
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
                    Logging::log("", &format!("Error: {:?}", e), line!(), file!());
                    None
                }
            },
            Err(e) => {
                Logging::log("", &format!("Error: {:?}", e), line!(), file!());
                None
            }
        }
    }

    pub fn finalize(
        &self,
        device: &Device,
        csprng: &mut Csprng,
        voter_ballot: &BallotDecrypted,
    ) -> BallotEncrypted {
        let contests = (0..self.contests.len())
            .map(|i| {
                self.contests[i].finalize(
                    device,
                    csprng,
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
            label: self.label.clone(),
            contests,
            confirmation_code: self.confirmation_code,
        }
    }
}
