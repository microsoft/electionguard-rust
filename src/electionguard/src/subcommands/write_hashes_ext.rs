// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{Context, Result};

use eg::{extended_base_hash::ExtendedBaseHash, serializable::SerializablePretty, eg::Eg};

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{load_election_parameters, load_hashes, load_joint_public_key},
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct WriteExtendedBaseHash {
    /// File to which to write the extended.
    /// Default is in the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for WriteExtendedBaseHash {
    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut eg = {
            let csprng = subcommand_helper
                .build_csprng()?
                .write_str("WriteExtendedBaseHash")
                .finish();
            Eg::from_csprng(csprng)
        };
        let eg = &mut eg;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let _election_parameters =
            load_election_parameters(eg, &subcommand_helper.artifacts_dir)?;

        //? TODO: Do we need a command line arg to specify the hashes source?
        let _hashes = load_hashes(eg, &subcommand_helper.artifacts_dir)?;

        //? TODO: Do we need a command line arg to specify the joint election public key source?
        let _joint_public_key =
            load_joint_public_key(eg, &subcommand_helper.artifacts_dir)?;

        let extended_base_hash = ExtendedBaseHash::get_or_compute(eg)?;

        let (mut stdiowrite, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(self.out_file.as_ref(), Some(&ArtifactFile::ExtendedBaseHash))?;

        extended_base_hash
            .to_stdiowrite_pretty(stdiowrite.as_mut())
            .with_context(|| format!("Writing hashes ext to: {}", path.display()))?;

        drop(stdiowrite);

        println!("Wrote hashes ext to: {}", path.display());

        Ok(())
    }
}
