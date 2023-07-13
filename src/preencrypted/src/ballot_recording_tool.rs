use std::str::FromStr;

use crate::ballot::BallotPreEncrypted;
use anyhow::Result;
use eg::{ballot_style::BallotStyle, election_record::PreVotingData, hash::HValue};

pub struct BallotRecordingTool {
    /// The election record header.
    pub header: PreVotingData,

    /// The ballot style to generate a ballot for.
    pub ballot_style: BallotStyle,
}

impl BallotRecordingTool {
    pub fn new(header: PreVotingData, ballot_style: BallotStyle) -> BallotRecordingTool {
        BallotRecordingTool {
            header: header,
            ballot_style: ballot_style,
        }
    }

    /// Regenerates a pre-encrypted ballot from the primary nonce and matches it against the provided ballot.
    /// Returns true if the ballots match.
    pub fn regenerate_and_match(
        &self,
        ballot: &BallotPreEncrypted,
        ballot_style: &BallotStyle,
        primary_nonce: &HValue,
    ) -> (Option<BallotPreEncrypted>, bool) {
        let regenerated_ballot =
            BallotPreEncrypted::new_with(&self.header, ballot_style, &primary_nonce.0, true);
        if *ballot != regenerated_ballot {
            eprintln!("Ballot mismatch: {:?} != {:?}.", ballot, regenerated_ballot);
            return (None, false);
        }

        eprintln!("Ballot matched");
        (Some(regenerated_ballot), true)
    }

    /// Reads a list of confirmation codes from a file.
    pub fn metadata_from_stdioread(
        &self,
        stdioread: &mut dyn std::io::Read,
    ) -> Result<Vec<HValue>> {
        let mut buffer = String::new();
        stdioread.read_to_string(&mut buffer).unwrap();
        let codes: Vec<&str> = buffer.trim().split('\n').collect();

        Ok(codes
            .iter()
            .map(|cc| HValue::from_str(cc).unwrap())
            .collect())
    }
}
