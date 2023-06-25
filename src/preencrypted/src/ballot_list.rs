use std::{collections::HashMap, fs, path::Path, time::SystemTime, time::UNIX_EPOCH};

use util::{
    csprng::Csprng,
    file::{read_path, write_path},
    logging::Logging,
};

use eg::{device::Device, election_record::ElectionRecordHeader, hash::HValue};

use crate::ballot::BallotPreEncrypted;

/// Many pre-encrypted ballots.
#[derive(Debug)]
pub struct BallotListPreEncrypted {
    /// Label
    pub label: String,

    /// A list of pre-encrypted ballots
    pub ballots: Vec<BallotPreEncrypted>,

    /// Primary nonces
    pub primary_nonces: Vec<HValue>,
}

impl BallotListPreEncrypted {
    pub fn read_from_directory(path: &Path) -> Option<Self> {
        // if !path.is_dir() {
        //     return None;
        // }
        // let label = path.file_name().unwrap().to_str().unwrap().to_string();

        // let mut codes_to_nonces = <HashMap<HValue, HValue>>::new();
        // let nonce_file = String::from_utf8(read_path(&path.join("primary-nonces.json"))).unwrap();
        // let (confirmation_codes, primary_nonces): (Vec<HValue>, Vec<HValue>) =
        //     serde_json::from_str(&nonce_file).unwrap();

        // (0..confirmation_codes.len()).for_each(|i| {
        //     codes_to_nonces.insert(confirmation_codes[i], primary_nonces[i]);
        // });

        // let mut ballots = Vec::new();
        // let mut primary_nonces = Vec::new();
        // match fs::read_dir(path) {
        //     Ok(entries) => {
        //         for entry in entries {
        //             let entry = entry.unwrap();
        //             let path = entry.path();
        //             if path.is_file()
        //                 && path
        //                     .file_name()
        //                     .unwrap()
        //                     .to_str()
        //                     .unwrap()
        //                     .starts_with("ballot-")
        //             {
        //                 match BallotPreEncrypted::try_new_from_file(&path) {
        //                     Some(ballot) => ballots.push(ballot),
        //                     None => {
        //                         Logging::log(
        //                             "",
        //                             &format!("Error reading ballot file {:?}", path),
        //                             line!(),
        //                             file!(),
        //                         );
        //                         return None;
        //                     }
        //                 }
        //                 let crypto_hash = ballots[ballots.len() - 1].get_confirmation_code();

        //                 match codes_to_nonces.get(&crypto_hash) {
        //                     Some(nonce) => primary_nonces.push(nonce.clone()),
        //                     None => {
        //                         Logging::log(
        //                             "",
        //                             &format!("No nonce found for ballot {:?}", crypto_hash),
        //                             line!(),
        //                             file!(),
        //                         );
        //                         return None;
        //                     }
        //                 }
        //             }
        //         }
        //     }
        //     Err(_) => {
        //         Logging::log("", "Error reading directory", line!(), file!());
        //         return None;
        //     }
        // }

        // Some(BallotListPreEncrypted {
        //     label,
        //     ballots,
        //     primary_nonces,
        // })
        None
    }
}
