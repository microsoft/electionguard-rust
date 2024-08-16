// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::path::PathBuf;

use anyhow::{Context, Result};

use eg::{pre_voting_data::PreVotingData, serializable::SerializablePretty};

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{
        load_election_parameters, load_hashes, load_hashes_ext, load_joint_election_public_key,
        ElectionManifestSource,
    },
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct WritePreVotingData {
    /// File to which to write the extended.
    /// Default is in the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for WritePreVotingData {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng(b"WritePreVotingData")?;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters =
            load_election_parameters(&subcommand_helper.artifacts_dir, &mut csprng)?;

        //? TODO: Do we need a command line arg to specify the election manifest source?
        let election_manifest_source =
            ElectionManifestSource::ArtifactFileElectionManifestCanonical;
        let election_manifest =
            election_manifest_source.load_election_manifest(&subcommand_helper.artifacts_dir)?;

        //? TODO: Do we need a command line arg to specify the hashes source?
        let hashes = load_hashes(&subcommand_helper.artifacts_dir)?;

        //? TODO: Do we need a command line arg to specify the joint election public key source?
        let joint_election_public_key =
            load_joint_election_public_key(&subcommand_helper.artifacts_dir, &election_parameters)?;

        //? TODO: Do we need a command line arg to specify the hashes_ext source?
        let hashes_ext = load_hashes_ext(&subcommand_helper.artifacts_dir)?;

        let pre_voting_data = PreVotingData {
            parameters: election_parameters,
            manifest: election_manifest,
            hashes,
            public_key: joint_election_public_key,
            hashes_ext,
        };

        let (mut stdiowrite, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(&self.out_file, Some(ArtifactFile::PreVotingData))?;

        pre_voting_data
            .to_stdiowrite_pretty(stdiowrite.as_mut())
            .with_context(|| format!("Writing pre voting data to: {}", path.display()))?;

        drop(stdiowrite);

        eprintln!("Wrote pre voting data to: {}", path.display());

        Ok(())
    }
}
