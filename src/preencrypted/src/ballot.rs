use std::{fs, path::PathBuf};

use crate::{confirmation_code::confirmation_code, contest::ContestPreEncrypted};
use anyhow::{anyhow, Context, Result};
use eg::{
    ballot::{BallotEncrypted, BallotState},
    ballot_style::BallotStyle,
    contest::{Contest, ContestEncrypted},
    contest_selection::ContestSelection,
    device::Device,
    election_manifest::ElectionManifest,
    election_record::PreVotingData,
    hash::HValue,
};
use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, logging::Logging};
// use voter::ballot::BallotSelections;

/// A pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct BallotPreEncrypted {
    /// Ballot style name.
    pub ballot_style: String,

    /// Contests in this ballot
    pub contests: Vec<ContestPreEncrypted>,

    /// Confirmation code
    pub confirmation_code: HValue,
}

/// A plaintext ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct VoterSelection {
    /// Ballot Style.
    pub ballot_style: String,

    /// Plaintext selections made by the voter.
    pub selections: Vec<ContestSelection>,
}

impl VoterSelection {
    pub fn new_pick_random(
        manifest: &ElectionManifest,
        ballot_style: &BallotStyle,
        csprng: &mut Csprng,
    ) -> Self {
        Self {
            ballot_style: ballot_style.label.clone(),
            selections: ballot_style
                .contests
                .iter()
                .map(|i| {
                    let contest = &manifest.contests[*i as usize - 1];
                    ContestSelection::new_pick_random(
                        csprng,
                        contest.selection_limit,
                        contest.options.len(),
                    )
                })
                .collect(),
        }
    }

    /// Reads a `VoterSelection` from a `std::io::Write`.
    pub fn from_stdioread(stdioread: &mut dyn std::io::Read) -> Result<Self> {
        let selection: Self =
            serde_json::from_reader(stdioread).context("Reading VoterSelection")?;

        Ok(selection)
    }

    /// Writes a `VoterSelection` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .context("Error serializing voter selection")?;

        ser.into_inner()
            .write_all(b"\n")
            .context("Error writing serialized voter selection to file")
    }
}

impl PartialEq for BallotPreEncrypted {
    fn eq(&self, other: &Self) -> bool {
        self.confirmation_code == other.confirmation_code
            && self.contests.as_slice() == other.contests.as_slice()
    }
}

impl BallotPreEncrypted {
    pub fn new_with(
        header: &PreVotingData,
        ballot_style: &BallotStyle,
        primary_nonce: &[u8],
        store_nonces: bool,
    ) -> BallotPreEncrypted {
        let b_aux = "Sample aux information.".as_bytes();

        // Find contests in manifest corresponding to requested ballot style
        let contests_to_encrypt = ballot_style
            .contests
            .iter()
            .map(|i| header.manifest.contests[*i as usize - 1].clone())
            .collect::<Vec<Contest>>();

        let contests = contests_to_encrypt
            .iter()
            .map(|c| ContestPreEncrypted::new(header, primary_nonce.as_ref(), store_nonces, c))
            .collect();
        let confirmation_code = confirmation_code(&header.hashes_ext.h_e, &contests, b_aux);

        BallotPreEncrypted {
            ballot_style: ballot_style.label.clone(),
            contests,
            confirmation_code,
        }
    }

    pub fn new(
        pv_data: &PreVotingData,
        ballot_style: &BallotStyle,
        csprng: &mut Csprng,
        store_nonces: bool,
    ) -> (BallotPreEncrypted, HValue) {
        let mut primary_nonce = [0u8; 32];
        (0..32).for_each(|i| primary_nonce[i] = csprng.next_u8());

        (
            BallotPreEncrypted::new_with(pv_data, ballot_style, &primary_nonce, store_nonces),
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

    pub fn finalize(
        &self,
        device: &Device,
        csprng: &mut Csprng,
        voter_ballot: &VoterSelection,
    ) -> BallotEncrypted {
        let contests = (0..self.contests.len())
            .map(|i| {
                self.contests[i].finalize(
                    device,
                    csprng,
                    &voter_ballot.selections[i].vote,
                    device.header.manifest.contests[i].selection_limit,
                )
            })
            .collect::<Vec<ContestEncrypted>>();

        BallotEncrypted::new(
            contests.as_slice(),
            BallotState::Cast,
            self.confirmation_code,
            &device.header.parameters.varying_parameters.date,
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
