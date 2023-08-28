// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{Context, Result};

use eg::hashes::Hashes;

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{load_election_parameters, ElectionManifestSource},
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct WriteHashes {
    /// File to which to write the hashes.
    /// Default is the election parameters file in the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,

    /// Whether to write extended hashes.
    #[arg(long, default_value_t = false)]
    extended: bool,
}

impl Subcommand for WriteHashes {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng(b"WriteHashes")?;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters =
            load_election_parameters(&subcommand_helper.artifacts_dir, &mut csprng)?;

        //? TODO: Do we need a command line arg to specify the election manifest source?
        let election_manifest_source =
            ElectionManifestSource::ArtifactFileElectionManifestCanonical;
        let election_manifest =
            election_manifest_source.load_election_manifest(&subcommand_helper.artifacts_dir)?;

        let hashes = Hashes::compute(&election_parameters, &election_manifest)?;

        let (mut stdiowrite, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(&self.out_file, Some(ArtifactFile::Hashes))?;

        hashes
            .to_stdiowrite(stdiowrite.as_mut())
            .with_context(|| format!("Writing hashes to: {}", path.display()))?;

        drop(stdiowrite);

        eprintln!("Wrote hashes to: {}", path.display());

        Ok(())
    }
}
