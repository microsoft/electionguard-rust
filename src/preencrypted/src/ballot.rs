use std::{fs, path::PathBuf, time::SystemTime};

use anyhow::{anyhow, Result};
use eg::{
    ballot::{BallotDecrypted, BallotEncrypted},
    contest::ContestEncrypted,
    device::Device,
    election_record::ElectionRecordHeader,
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

    pub fn new_with(header: &ElectionRecordHeader, primary_nonce: &[u8]) -> BallotPreEncrypted {
        // TODO: Find contests in manifest corresponding to requested ballot style

        let label = "Sample Election".to_string();
        let b_aux = "Sample Aux Info".as_bytes();

        let contests = header
            .manifest
            .contests
            .iter()
            .map(|c| ContestPreEncrypted::new(header, primary_nonce.as_ref(), c))
            .collect();
        let confirmation_code = confirmation_code(&header.hashes.h_e, &contests, b_aux);

        BallotPreEncrypted {
            label,
            contests,
            confirmation_code,
        }
    }

    pub fn new(header: &ElectionRecordHeader, csprng: &mut Csprng) -> (BallotPreEncrypted, HValue) {
        let mut primary_nonce = [0u8; 32];
        (0..32).for_each(|i| primary_nonce[i] = csprng.next_u8());

        (
            BallotPreEncrypted::new_with(header, &primary_nonce),
            HValue(primary_nonce),
        )
    }

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

    fn unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
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
                    device.header.manifest.contests[i].selection_limit,
                )
            })
            .collect::<Vec<ContestEncrypted>>();

        BallotEncrypted {
            date: Self::unix_timestamp().to_string(),
            device: device.get_uuid().clone(),
            label: self.label.clone(),
            contests,
            confirmation_code: self.confirmation_code,
        }
    }

    /// Returns a pretty JSON `String` representation of `BallotPreEncrypted`.
    /// The final line will end with a newline.
    pub fn to_json(&self) -> String {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }

    /// Reads `BallotPreEncrypted` from a `std::io::Read`.
    pub fn from_reader(io_read: &mut dyn std::io::Read) -> Result<BallotPreEncrypted> {
        serde_json::from_reader(io_read)
            .map_err(|e| anyhow!("Error parsing BallotPreEncrypted: {}", e))
    }
}
