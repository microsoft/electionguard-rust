// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{num::NonZeroU16, path::PathBuf};

use anyhow::{Context, Result};

use eg::{hashes::Hashes, hashes_ext::HashesExt};

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{
        load_election_parameters, load_guardian_public_key, load_joint_election_public_key,
        ElectionManifestSource,
    },
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

/// Writes the hashes to a file.
/// The election parameters and election manifest are read from the artifacts dir.
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

        let guardian_public_keys = (1..election_parameters.varying_parameters.n + 1)
            .map(|i| {
                load_guardian_public_key(
                    Some(NonZeroU16::new(i).unwrap()),
                    &None,
                    &subcommand_helper.artifacts_dir,
                    &election_parameters,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let jepk = load_joint_election_public_key(&None, &subcommand_helper.artifacts_dir)?;
        let hashes = Hashes::new(&election_parameters, &election_manifest);

        let (mut bx_write, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(&self.out_file, Some(ArtifactFile::Hashes))?;

        hashes
            .to_stdiowrite(bx_write.as_mut())
            .with_context(|| format!("Writing hashes to: {}", path.display()))?;

        drop(bx_write);

        if self.extended {
            let hashes_ext =
                HashesExt::new(&election_parameters, &hashes, &jepk, &guardian_public_keys);

            let (mut bx_write, path) = subcommand_helper
                .artifacts_dir
                .out_file_stdiowrite(&None, Some(ArtifactFile::HashesExt))?;

            hashes_ext
                .to_stdiowrite(bx_write.as_mut())
                .with_context(|| format!("Writing hashes (extended) to: {}", path.display()))?;

            drop(bx_write);
        }

        eprintln!("Wrote hashes to: {}", path.display());

        Ok(())
    }
}
