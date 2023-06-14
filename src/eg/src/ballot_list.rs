use std::{collections::HashMap, fs, path::Path, time::SystemTime, time::UNIX_EPOCH};

use util::csprng::Csprng;

use crate::{
    ballot::{BallotConfig, BallotPreEncrypted},
    fixed_parameters::FixedParameters,
};

/// Many pre-encrypted ballots.
#[derive(Debug)]
pub struct BallotListPreEncrypted {
    /// Label
    pub label: String,

    /// A list of pre-encrypted ballots
    pub ballots: Vec<BallotPreEncrypted>,

    /// Primary nonces
    pub primary_nonces: Vec<String>,
}

impl BallotListPreEncrypted {
    pub fn new(
        config: &BallotConfig,
        fixed_parameters: &FixedParameters,
        csprng: &mut Csprng,
        path: &Path,
        num_ballots: usize,
    ) -> Self {
        // let mut ballot_list: Self;
        let mut ballots = Vec::with_capacity(num_ballots);
        let mut primary_nonces = Vec::with_capacity(num_ballots);
        let label: String;
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(n) => {
                label = format!("{}", n.as_secs());
            }
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        }
        let path = path.join(label.clone());
        fs::create_dir_all(&path).unwrap();
        let mut confirmation_codes = Vec::with_capacity(num_ballots);

        for b_idx in 0..num_ballots {
            let (ballot, primary_nonce) =
                BallotPreEncrypted::new(&config, fixed_parameters, csprng);

            println!("Primary nonce:\t{}", primary_nonce);
            primary_nonces.push(primary_nonce);
            ballots.push(ballot);
            confirmation_codes.push(ballots[b_idx].get_crypto_hash().clone());
            fs::write(
                path.join(format!("ballot-{}.json", confirmation_codes[b_idx])),
                serde_json::to_string(&ballots[b_idx]).unwrap(),
            )
            .unwrap();
        }

        fs::write(
            path.join("primary-nonces.json"),
            serde_json::to_string(&vec![confirmation_codes, primary_nonces.clone()]).unwrap(),
        )
        .unwrap();

        BallotListPreEncrypted {
            label,
            ballots,
            primary_nonces,
        }
    }

    pub fn read_from_directory(path: &Path) -> Option<Self> {
        if !path.is_dir() {
            return None;
        }
        let label = path.file_name().unwrap().to_str().unwrap().to_string();

        let mut codes_to_nonces = <HashMap<String, String>>::new();
        match fs::read_to_string(path.join("primary-nonces.json")) {
            Ok(nonce_file) => {
                let (confirmation_codes, primary_nonces): (Vec<String>, Vec<String>) =
                    serde_json::from_str(&nonce_file).unwrap();

                (0..confirmation_codes.len()).for_each(|i| {
                    codes_to_nonces
                        .insert(confirmation_codes[i].clone(), primary_nonces[i].clone());
                });
            }
            Err(e) => {
                eprintln!("Error reading nonce file: {}", e);
                return None;
            }
        }

        let mut ballots = Vec::new();
        let mut primary_nonces = Vec::new();
        match fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry.unwrap();
                    let path = entry.path();
                    if path.is_file()
                        && path
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .starts_with("ballot-")
                    {
                        match BallotPreEncrypted::try_new_from_file(&path) {
                            Some(ballot) => ballots.push(ballot),
                            None => {
                                eprintln!("Error reading ballot file {:?}", path);
                                return None;
                            }
                        }
                        let crypto_hash = ballots[ballots.len() - 1].get_crypto_hash().to_string();

                        match codes_to_nonces.get(&crypto_hash) {
                            Some(nonce) => primary_nonces.push(nonce.clone()),
                            None => {
                                eprintln!("No nonce found for ballot {:?}", crypto_hash);
                                return None;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                eprintln!("Error reading directory");
                return None;
            }
        }

        Some(BallotListPreEncrypted {
            label,
            ballots,
            primary_nonces,
        })
    }
}
