use std::{fs, path::PathBuf, time::SystemTime};

use crate::{confirmation_code::confirmation_code, contest::ContestPreEncrypted};
use anyhow::{anyhow, Context, Result};
use eg::{
    ballot::{BallotEncrypted, BallotState},
    contest::ContestEncrypted,
    device::Device,
    election_record::ElectionRecordHeader,
    hash::HValue,
};
use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, logging::Logging};
use voter::ballot::BallotSelections;

/// A pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct BallotPreEncrypted {
    /// Contests in this ballot
    pub contests: Vec<ContestPreEncrypted>,

    /// Confirmation code
    pub confirmation_code: HValue,
}

impl PartialEq for BallotPreEncrypted {
    fn eq(&self, other: &Self) -> bool {
        self.confirmation_code == other.confirmation_code
            && self.contests.as_slice() == other.contests.as_slice()
    }
}

impl BallotPreEncrypted {
    pub fn new_with(
        header: &ElectionRecordHeader,
        primary_nonce: &[u8],
        store_nonces: bool,
    ) -> BallotPreEncrypted {
        // TODO: Find contests in manifest corresponding to requested ballot style

        let b_aux = "Sample Aux Info".as_bytes();

        let contests = header
            .manifest
            .contests
            .iter()
            .map(|c| ContestPreEncrypted::new(header, primary_nonce.as_ref(), store_nonces, c))
            .collect();
        let confirmation_code = confirmation_code(&header.hashes_ext.h_e, &contests, b_aux);

        BallotPreEncrypted {
            contests,
            confirmation_code,
        }
    }

    pub fn new(
        header: &ElectionRecordHeader,
        csprng: &mut Csprng,
        store_nonces: bool,
    ) -> (BallotPreEncrypted, HValue) {
        let mut primary_nonce = [0u8; 32];
        (0..32).for_each(|i| primary_nonce[i] = csprng.next_u8());

        (
            BallotPreEncrypted::new_with(header, &primary_nonce, store_nonces),
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
        voter_ballot: &BallotSelections,
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

        BallotEncrypted::new(
            contests.as_slice(),
            BallotState::Cast,
            self.confirmation_code,
            Self::unix_timestamp().to_string().as_str(),
            device.get_uuid(),
        )
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

    /// Reads a `BallotPreEncrypted` from a `std::io::Write`.
    pub fn from_stdioread(stdioread: &mut dyn std::io::Read) -> Result<Self> {
        let ballot: Self =
            serde_json::from_reader(stdioread).context("Reading BallotPreEncrypted")?;

        Ok(ballot)
    }

    /// Writes a `BallotPreEncrypted` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .context("Error writing pre-encrypted ballot")?;

        ser.into_inner()
            .write_all(b"\n")
            .context("Error writing pre-encrypted ballot file")
    }
}
