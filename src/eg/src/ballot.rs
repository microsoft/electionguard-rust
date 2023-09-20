// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

use crate::{
    confirmation_code::confirmation_code,
    contest_encrypted::ContestEncrypted,
    contest_selection::{ContestSelection, ContestSelectionIndex},
    device::Device,
    election_manifest::ContestIndex,
    hash::HValue,
    vec1::Vec1,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BallotState {
    Uncast,
    Cast,
    Challenged,
}

/// An encrypted ballot.
#[derive(Debug, Serialize, Deserialize)]
pub struct BallotEncrypted {
    /// Contests in this ballot
    pub contests: Vec1<ContestEncrypted>,

    /// Confirmation code
    pub confirmation_code: HValue,

    /// State of the ballot
    pub state: BallotState,

    /// Date (and time) of ballot generation
    pub date: String,

    /// Device that generated this ballot
    pub device: String,
    // TODO: Have an optional field to store election record data for pre-encrypted ballots
}

impl BallotEncrypted {
    pub fn new(
        contests: &Vec1<ContestEncrypted>,
        state: BallotState,
        confirmation_code: HValue,
        date: &str,
        device: &str,
    ) -> BallotEncrypted {
        BallotEncrypted {
            contests: contests.clone(),
            state,
            confirmation_code,
            date: date.to_string(),
            device: device.to_string(),
        }
    }

    pub fn new_from_selections(
        device: &Device,
        csprng: &mut Csprng,
        primary_nonce: &[u8],
        ctest_selections: &Vec1<ContestSelection>,
    ) -> BallotEncrypted {
        let mut contests = Vec1::with_capacity(ctest_selections.len());

        for i in 1..ctest_selections.len() + 1 {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let c_idx = ContestIndex::from_one_based_index(i as u32).unwrap();

            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            let s_idx = ContestSelectionIndex::from_one_based_index(i as u32).unwrap();

            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            contests
                .try_push(ContestEncrypted::new(
                    device,
                    csprng,
                    primary_nonce,
                    device.header.manifest.contests.get(c_idx).unwrap(),
                    ctest_selections.get(s_idx).unwrap(),
                ))
                .unwrap();
        }

        // for (i, selection) in selections.iter().enumerate() {
        //     contests.push(ContestEncrypted::new(
        //         device,
        //         csprng,
        //         primary_nonce,
        //         &device.header.manifest.contests.get(i).unwrap(),
        //         selection,
        //     ));
        // }
        let confirmation_code =
            confirmation_code(&device.header.hashes_ext.h_e, &contests, &[0u8; 32]);

        BallotEncrypted {
            contests,
            state: BallotState::Uncast,
            confirmation_code,
            date: device.header.parameters.varying_parameters.date.clone(),
            device: device.uuid.clone(),
        }
    }

    pub fn contests(&self) -> &Vec1<ContestEncrypted> {
        &self.contests
    }

    pub fn confirmation_code(&self) -> &HValue {
        &self.confirmation_code
    }

    pub fn date(&self) -> &String {
        &self.date
    }

    pub fn device(&self) -> &String {
        &self.device
    }

    /// Writes a `BallotEncrypted` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .context("Error serializing voter selection")?;

        ser.into_inner()
            .write_all(b"\n")
            .context("Error writing serialized voter selection to file")
    }
}
