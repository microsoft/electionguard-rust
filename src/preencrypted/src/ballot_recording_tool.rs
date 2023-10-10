// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::str::FromStr;

use anyhow::Result;

use eg::{ballot_style::BallotStyleIndex, election_record::PreVotingData, hash::HValue};

use crate::ballot::BallotPreEncrypted;

pub struct BallotRecordingTool {
    /// The election record header.
    pub pre_voting_data: PreVotingData,

    /// The ballot style to record a ballot for.
    pub ballot_style_index: BallotStyleIndex,
}

impl BallotRecordingTool {
    pub fn new(
        pre_voting_data: PreVotingData,
        ballot_style_index: BallotStyleIndex,
    ) -> BallotRecordingTool {
        BallotRecordingTool {
            pre_voting_data,
            ballot_style_index,
        }
    }

    /// Regenerates a pre-encrypted ballot from the primary nonce and matches it against the provided ballot.
    /// Returns true if the ballots match.
    pub fn regenerate_and_match(
        &self,
        ballot: &BallotPreEncrypted,
        ballot_style_index: BallotStyleIndex,
        primary_nonce: &HValue,
    ) -> (Option<BallotPreEncrypted>, bool) {
        let regenerated_ballot = BallotPreEncrypted::new_with(
            &self.pre_voting_data,
            ballot_style_index,
            &primary_nonce.0,
            true,
        );
        if *ballot != regenerated_ballot {
            eprintln!("Ballot mismatch: {:?} != {:?}.", ballot, regenerated_ballot);
            return (None, false);
        }

        // eprintln!("Ballot matched");
        (Some(regenerated_ballot), true)
    }

    /// Reads a list of confirmation codes from a file.
    pub fn metadata_from_stdioread(
        &self,
        stdioread: &mut dyn std::io::Read,
    ) -> Result<Vec<HValue>> {
        let mut buffer = String::new();

        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        stdioread.read_to_string(&mut buffer).unwrap();
        let codes: Vec<&str> = buffer.trim().split('\n').collect();

        Ok(codes
            .iter()
            .map(|cc| {
                #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
                HValue::from_str(cc).unwrap()
            })
            .collect())
    }
}
