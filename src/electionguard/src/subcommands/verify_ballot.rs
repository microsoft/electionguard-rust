// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::{artifacts_dir::ArtifactsDir, subcommand_helper::SubcommandHelper, Subcommand};
use anyhow::{bail, Result};
use clap::Args;
use eg::{
    ballot::{BallotConfig, BallotDecrypted},
    device::Device,
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    example_election_manifest::{example_election_manifest, example_election_manifest_small},
    example_election_parameters::example_election_parameters,
    guardian::aggregate_public_keys,
    hashes::Hashes,
    key::PublicKey,
    nizk::ProofGuardian,
};
use preencrypted::{
    ballot_list::BallotListPreEncrypted, ballot_recording_tool::BallotRecordingTool,
};
use util::{file::read_path, logging::Logging};

#[derive(Args, Debug)]
pub(crate) struct VerifyBallot {
    /// File from which to read the election manifest.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Use the example election manifest.
    #[arg(long)]
    example_manifest: bool,

    /// Number of ballots to generate
    #[arg(short, long, default_value_t = 1)]
    num_ballots: usize,

    // Tag
    #[arg(long, default_value_t = String::from(""))]
    tag: String,
}

impl Subcommand for VerifyBallot {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng(b"VerifyStandardParameters")?;

        use eg::standard_parameters::STANDARD_PARAMETERS;
        let fixed_parameters = &*STANDARD_PARAMETERS;

        if self.example_manifest && self.manifest.is_some() {
            bail!("Specify either --example-manifest or --manifest, but not both.");
        }

        let election_parameters: ElectionParameters;
        let election_manifest: ElectionManifest;

        if self.example_manifest {
            election_parameters = example_election_parameters();
            election_manifest = example_election_manifest_small();
        } else {
            return Err(anyhow::anyhow!("Not implemented yet"));
        }

        let mut ballots: BallotListPreEncrypted;
        match BallotListPreEncrypted::read_from_directory(
            &subcommand_helper
                .artifacts_dir
                .dir_path
                .join(format!("ballots/{}", self.tag.as_str())),
        ) {
            Some(b) => ballots = b,
            None => bail!("Error reading ballots."),
        }

        let device = Device::new(
            "BallotRecordingDevice".to_string(),
            &config,
            &election_parameters,
        );

        for b_idx in 0..ballots.ballots.len() {
            Logging::log(
                "Pre-Encrypted",
                &format!("Verifying Ballot {}", b_idx + 1),
                line!(),
                file!(),
            );

            let pre_encrypted_ballot = &mut ballots.ballots[b_idx];
            assert!(BallotRecordingTool::verify_ballot(
                &device,
                &pre_encrypted_ballot,
                &ballots.primary_nonces[b_idx]
            ));

            BallotRecordingTool::regenerate_nonces(
                &device,
                pre_encrypted_ballot,
                &ballots.primary_nonces[b_idx],
            );

            let voter_ballot = BallotDecrypted::new_pick_random(
                &config,
                &mut csprng,
                String::from("Random Voter"),
            );

            let encrypted_ballot =
                pre_encrypted_ballot.finalize(&device, &mut csprng, &voter_ballot);

            encrypted_ballot.instant_verification_code(
                &device,
                &voter_ballot,
                ballots.primary_nonces[b_idx].as_ref(),
                &path.join(self.tag.as_str()),
            );

            BallotRecordingTool::verify_ballot_proofs(&device, &encrypted_ballot);
        }

        Ok(())
    }
}
