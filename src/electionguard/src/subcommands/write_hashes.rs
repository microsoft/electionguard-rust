// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use eg::{eg::Eg, hashes::Hashes, serializable::SerializablePretty};

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{
        //load_election_parameters,
        ElectionManifestSource,
    },
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
    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let eg = subcommand_helper.get_eg("WriteHashes")?;
        let _eg = eg.as_ref();
        anyhow::bail!("TODO: finish implementing WriteHashes");

        /*
        //? TODO: Do we need a command line arg to specify the election parameters source?
        let _election_parameters =
            load_election_parameters(eg, &subcommand_helper.artifacts_dir)?;

        //? TODO: Do we need a command line arg to specify the election manifest source?
        let election_manifest_source =
            ElectionManifestSource::ArtifactFileElectionManifestCanonical;
        let _election_manifest =
            election_manifest_source.load_election_manifest(&subcommand_helper.artifacts_dir)?;

        Hashes::get_or_compute(eg)?;
        let hashes = eg.hashes()?;

        let (mut stdiowrite, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(self.out_file.as_ref(), Some(&ArtifactFile::Hashes))?;

        hashes
            .to_stdiowrite_pretty(stdiowrite.as_mut())
            .with_context(|| format!("Writing hashes to: {}", path.display()))?;

        drop(stdiowrite);

        println!("Wrote hashes to: {}", path.display());

        Ok(())
        // */
    }
}
