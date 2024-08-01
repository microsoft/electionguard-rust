// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{Context, Result};

use eg::{hashes_ext::HashesExt, serialize::SerializablePretty};

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{load_election_parameters, load_hashes, load_joint_election_public_key},
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct WriteHashesExt {
    /// File to which to write the extended.
    /// Default is in the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for WriteHashesExt {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng(b"WriteHashesExt")?;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters =
            load_election_parameters(&subcommand_helper.artifacts_dir, &mut csprng)?;

        //? TODO: Do we need a command line arg to specify the hashes source?
        let hashes = load_hashes(&subcommand_helper.artifacts_dir)?;

        //? TODO: Do we need a command line arg to specify the joint election public key source?
        let joint_election_public_key =
            load_joint_election_public_key(&subcommand_helper.artifacts_dir, &election_parameters)?;

        let hashes_ext =
            HashesExt::compute(&election_parameters, &hashes, &joint_election_public_key);

        let (mut stdiowrite, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(&self.out_file, Some(ArtifactFile::HashesExt))?;

        hashes_ext
            .to_stdiowrite(stdiowrite.as_mut())
            .with_context(|| format!("Writing hashes ext to: {}", path.display()))?;

        drop(stdiowrite);

        eprintln!("Wrote hashes ext to: {}", path.display());

        Ok(())
    }
}
