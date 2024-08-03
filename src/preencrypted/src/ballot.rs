// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{collections::BTreeMap, fs, path::PathBuf};

use crate::{confirmation_code::confirmation_code, contest::ContestPreEncrypted};
use anyhow::{anyhow, Context, Result};
use eg::{
    ballot::{BallotEncrypted, BallotEncryptedError, BallotState},
    ballot_style::BallotStyleIndex,
    contest_selection::ContestSelection,
    device::Device,
    election_manifest::{ContestIndex, ElectionManifest},
    election_record::PreVotingData,
    hash::HValue,
    serializable::SerializablePretty,
    vec1::Vec1,
};
use serde::{Deserialize, Serialize};
use util::{csprng::Csprng, logging::Logging};
// use voter::ballot::BallotSelections;

/// A pre-encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct BallotPreEncrypted {
    /// Ballot style index.
    pub ballot_style_index: BallotStyleIndex,

    /// Contests in this ballot
    pub contests: Vec1<ContestPreEncrypted>,

    /// Confirmation code
    pub confirmation_code: HValue,
}

/// A plaintext ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct VoterSelection {
    /// Ballot style index.
    pub ballot_style_index: BallotStyleIndex,

    /// Plaintext selections made by the voter.
    pub selections: Vec1<ContestSelection>,
}

impl VoterSelection {
    pub fn new_pick_random(
        manifest: &ElectionManifest,
        ballot_style_index: BallotStyleIndex,
        csprng: &mut Csprng,
    ) -> Self {
        let mut selections = Vec1::new();
        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        let ballot_style = manifest.ballot_styles.get(ballot_style_index).unwrap();
        ballot_style.contests.iter().for_each(|i| {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let contest = manifest.contests.get(*i).unwrap();
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            selections
                .try_push(ContestSelection::new_pick_random(
                    csprng,
                    contest.selection_limit,
                    contest.options.len(),
                ))
                .unwrap();
        });

        Self {
            ballot_style_index,
            selections,
        }
    }

    /// Reads a `VoterSelection` from a `std::io::Write`.
    pub fn from_stdioread(stdioread: &mut dyn std::io::Read) -> Result<Self> {
        let selection: Self =
            serde_json::from_reader(stdioread).context("Reading VoterSelection")?;

        Ok(selection)
    }
}

impl SerializablePretty for BallotPreEncrypted {}

impl PartialEq for BallotPreEncrypted {
    fn eq(&self, other: &Self) -> bool {
        self.confirmation_code == other.confirmation_code && self.contests == other.contests
    }
}

impl BallotPreEncrypted {
    pub fn new_with(
        header: &PreVotingData,
        ballot_style_index: BallotStyleIndex,
        primary_nonce: &[u8],
        store_nonces: bool,
    ) -> BallotPreEncrypted {
        let b_aux = "Sample aux information.".as_bytes();

        // Find contests in manifest corresponding to requested ballot style
        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        let ballot_style = header
            .manifest
            .ballot_styles
            .get(ballot_style_index)
            .unwrap();

        let mut contests = Vec1::new();
        ballot_style.contests.iter().for_each(|i| {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let c = header.manifest.contests.get(*i).unwrap();
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            contests
                .try_push(ContestPreEncrypted::new(
                    header,
                    primary_nonce,
                    store_nonces,
                    c,
                    *i,
                ))
                .unwrap()
        });
        let confirmation_code = confirmation_code(&header.hashes_ext.h_e, &contests, b_aux);

        BallotPreEncrypted {
            ballot_style_index,
            contests,
            confirmation_code,
        }
    }

    pub fn new(
        pv_data: &PreVotingData,
        ballot_style_index: BallotStyleIndex,
        csprng: &mut Csprng,
        store_nonces: bool,
    ) -> (BallotPreEncrypted, HValue) {
        let mut primary_nonce = [0u8; 32];
        (0..32).for_each(|i| primary_nonce[i] = csprng.next_u8());

        (
            BallotPreEncrypted::new_with(pv_data, ballot_style_index, &primary_nonce, store_nonces),
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
    ) -> Result<BallotEncrypted, BallotEncryptedError> {
        let mut contests = BTreeMap::new();

        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        for i in 1..=self.contests.len() {
            let c_idx = ContestIndex::from_one_based_index(i as u32).unwrap();
            let contest = self.contests.get(c_idx).unwrap();
            let correct_content_index = contest.contest_index;

            let c = device
                .header
                .manifest
                .contests
                .get(correct_content_index)
                .unwrap();
            contests
                .insert(
                    correct_content_index,
                    contest
                        .finalize(
                            device,
                            csprng,
                            voter_ballot.selections.get(c_idx).unwrap().get_vote(),
                            c.selection_limit,
                            c.options.len(),
                        )
                        .map_err(|err| BallotEncryptedError::ProofError { err })?,
                )
                .unwrap();
        }

        Ok(BallotEncrypted::new(
            self.ballot_style_index,
            &contests,
            BallotState::Cast,
            self.confirmation_code,
            &device.header.parameters.varying_parameters.date,
            device.get_uuid(),
        ))
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
}

impl SerializablePretty for VoterSelection {}
