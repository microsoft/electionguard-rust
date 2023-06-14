use std::{collections::HashMap, fs, path::Path, time::SystemTime, time::UNIX_EPOCH};

use util::{
    csprng::Csprng,
    file::{read_path, write_path},
    logging::Logging,
};

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
    fn print_ballot(i: usize, ballot: &BallotPreEncrypted, primary_nonce: &str) {
        let tag = "Pre-Encrypted";
        Logging::log(tag, &format!("Ballot {}", i), line!(), file!());
        Logging::log(tag, "  Primary Nonce", line!(), file!());
        Logging::log(tag, &format!("    {}", primary_nonce), line!(), file!());
        Logging::log(tag, "  Confirmation Code", line!(), file!());
        Logging::log(
            tag,
            &format!("    {}", ballot.confirmation_code.0.to_string()),
            line!(),
            file!(),
        );
        Logging::log(tag, "  Contests", line!(), file!());
        ballot.get_contests().iter().for_each(|c| {
            Logging::log(
                tag,
                &format!("    {}", c.crypto_hash.to_string()),
                line!(),
                file!(),
            );
        });
    }
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
            Self::print_ballot(b_idx + 1, &ballot, &primary_nonce);
            primary_nonces.push(primary_nonce);
            ballots.push(ballot);
            confirmation_codes.push(ballots[b_idx].get_confirmation_code().0.clone());
            fs::write(
                path.join(format!("ballot-{}.json", confirmation_codes[b_idx])),
                serde_json::to_string(&ballots[b_idx]).unwrap(),
            )
            .unwrap();
        }

        write_path(
            &path.join("primary-nonces.json"),
            serde_json::to_string(&vec![confirmation_codes, primary_nonces.clone()])
                .unwrap()
                .as_bytes(),
        );

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
        let nonce_file = String::from_utf8(read_path(&path.join("primary-nonces.json"))).unwrap();
        let (confirmation_codes, primary_nonces): (Vec<String>, Vec<String>) =
            serde_json::from_str(&nonce_file).unwrap();

        (0..confirmation_codes.len()).for_each(|i| {
            codes_to_nonces.insert(confirmation_codes[i].clone(), primary_nonces[i].clone());
        });

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
                                Logging::log(
                                    "",
                                    &format!("Error reading ballot file {:?}", path),
                                    line!(),
                                    file!(),
                                );
                                return None;
                            }
                        }
                        let crypto_hash =
                            ballots[ballots.len() - 1].get_confirmation_code().0.clone();

                        match codes_to_nonces.get(&crypto_hash) {
                            Some(nonce) => primary_nonces.push(nonce.clone()),
                            None => {
                                Logging::log(
                                    "",
                                    &format!("No nonce found for ballot {:?}", crypto_hash),
                                    line!(),
                                    file!(),
                                );
                                return None;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                Logging::log("", "Error reading directory", line!(), file!());
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
