// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use eg::{
    ballot::BallotEncrypted, contest_selection::ContestSelection, device::Device,
    election_record::PreVotingData,
};

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{
        load_election_parameters, load_hashes, load_hashes_ext, load_joint_election_public_key,
        ElectionManifestSource,
    },
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct VoterWriteRandomSelection {
    /// File to which to write the random selections.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for VoterWriteRandomSelection {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(
        &mut self,
        subcommand_helper: &mut crate::subcommand_helper::SubcommandHelper,
    ) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng(b"VoterWriteRandomSelection")?;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters =
            load_election_parameters(&subcommand_helper.artifacts_dir, &mut csprng)?;

        //? TODO: Do we need a command line arg to specify the election manifest source?
        let election_manifest_source =
            ElectionManifestSource::ArtifactFileElectionManifestCanonical;
        let election_manifest =
            election_manifest_source.load_election_manifest(&subcommand_helper.artifacts_dir)?;

        let hashes = load_hashes(&subcommand_helper.artifacts_dir)?;
        let hashes_ext = load_hashes_ext(&subcommand_helper.artifacts_dir)?;
        let jepk =
            load_joint_election_public_key(&subcommand_helper.artifacts_dir, &election_parameters)?;

        let record_header = PreVotingData::new(
            election_manifest.clone(),
            election_parameters,
            hashes,
            hashes_ext,
            jepk,
        );
        let device = Device::new("Ballot Recording Tool", record_header.clone());

        let contest_selections = election_manifest
            .contests
            .iter()
            .map(|c| {
                ContestSelection::new_pick_random(&mut csprng, c.selection_limit, c.options.len())
            })
            .collect::<Vec<_>>()
            .try_into()?;

        let ballot = BallotEncrypted::new_from_selections(
            &device,
            &mut csprng,
            record_header.hashes_ext.h_e.as_ref(),
            &contest_selections,
        );

        // distinct from `ballot.date`
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let (mut stdiowrite, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
            &self.out_file,
            Some(ArtifactFile::EncryptedBallot(
                timestamp as u128,
                ballot.confirmation_code,
            )),
        )?;

        ballot
            .to_stdiowrite(stdiowrite.as_mut())
            .with_context(|| format!("Writing ballot to: {}", path.display()))?;

        drop(stdiowrite);

        eprintln!("Wrote ballot to: {}", path.display());

        Ok(())
    }
}
