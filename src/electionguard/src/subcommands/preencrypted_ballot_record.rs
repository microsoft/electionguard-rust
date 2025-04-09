// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{bail, Context, Result};

use eg::{
    ballot_style::BallotStyleIndex, pre_voting_data::PreVotingData, hash::HValue,
    serializable::SerializablePretty,
};
use preencrypted::{
    ballot::{BallotPreEncrypted, VoterSelection},
    ballot_recording_tool::BallotRecordingTool,
};
use util::file::create_path;

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{
        load_election_parameters, load_hashes, load_extended_base_hash, load_joint_public_key,
        ElectionManifestSource,
    },
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

/// Record voter selections on a pre-encrypted ballot.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct PreEncryptedBallotRecord {
    /// Number of ballots to verify.
    #[arg(short, long, default_value_t = 1)]
    num_ballots: usize,

    /// Path for voter selections.
    #[arg(short, long)]
    selections_in: u128,

    /// Path for pre-encrypted ballots.
    #[arg(short, long)]
    ballots_in: u128,

    /// The ballot style to verify.
    #[arg(short, long, default_value_t = 0)]
    ballot_style_index: u32,
}

impl Subcommand for PreEncryptedBallotRecord {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut eg = {
            let csprng = subcommand_helper
                .build_csprng()?
                .write_str("PreEncryptedBallotRecord")
                .write_u64(self.ballot_style_index)
                .finish();
            Eg::from_csprng(csprng)
        };
        let eg = &mut eg;

        let pv_data = load_pre_voting_data(&subcommand_helper.artifacts_dir)?;

        let ballot_style_index = BallotStyleIndex::from_one_based_index(self.ballot_style_index)
                .unwrap_or_else(|| anyhow!("Ballot style is required to record pre-encrypted ballots."));

        let tool = BallotRecordingTool::new(pre_voting_data.clone(), ballot_style_index);

        let codes = {
            let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                &None, Some(&ArtifactFile::PreEncryptedBallotMetadata(self.ballots_in)))?;
            tool.metadata_from_stdioread(&mut stdioread)?
        };

        create_path(
            &subcommand_helper
                .artifacts_dir
                .dir_path
                .join(format!("record/ballots/{}", self.ballots_in)),
        );

        for b_idx in 1..codes.len() + 1 {
            let pre_encrypted_ballot = {
                let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                    &None,
                    Some(&ArtifactFile::PreEncryptedBallot(
                        self.ballots_in,
                        codes[b_idx - 1],
                    )),
                )?;
                BallotPreEncrypted::from_stdioread(&mut stdioread)?
            };

            let nonce = {
                let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                    &None,
                    Some(&ArtifactFile::PreEncryptedBallotNonce(
                        self.ballots_in,
                        codes[b_idx - 1],
                    )),
                )?;
                HValue::from_stdioread(&mut stdioread)?
            };

            let (regenerated_ballot, matched) =
                tool.regenerate_and_match(&pre_encrypted_ballot, ballot_style_index, &nonce);
            assert!(matched);

            if matched {
                #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
                let regenerated_ballot = regenerated_ballot.unwrap();
                let voter_ballot = {
                    let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                        &None,
                        Some(&ArtifactFile::VoterSelection(
                            self.selections_in,
                            b_idx as u64,
                        )),
                    )?;

                    VoterSelection::from_stdioread(&mut stdioread)?
                };
                let encrypted_ballot =
                    regenerated_ballot.finalize(&device, csprng, &voter_ballot)?;

                let (mut bx_write, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
                    &None,
                    Some(&ArtifactFile::EncryptedBallot(
                        self.ballots_in,
                        encrypted_ballot.confirmation_code,
                    )),
                )?;

                encrypted_ballot
                    .to_stdiowrite_pretty(bx_write.as_mut())
                    .with_context(|| format!("Writing encrypted ballot to: {}", path.display()))?;
                drop(bx_write);
            } else {
                println!(
                    "Regenerated ballot with nonce {} does not match ballot {}",
                    nonce, b_idx
                );
            }
        }

        Ok(())

        // TODO: Encrypt them
        // subcommand_helper.artifacts_dir.out_file_write(
        //     &None,
        //     ArtifactFile::PreEncryptedBallotNonces(label as u128),
        //     format!("pre-encrypted ballot nonces").as_str(),
        //     format!("{:?}", &vec![confirmation_codes, primary_nonces.clone()]).as_bytes(),
        // )
    }
}
