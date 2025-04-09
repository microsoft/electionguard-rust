// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{Context, Result};

use eg::{
    joint_public_key::JointPublicKey, serializable::SerializablePretty,
    eg::Eg,
};

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{load_all_guardian_public_keys, load_election_parameters},
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct WriteJointPublicKey {
    /// File to which to write the election public key.
    /// Default is in the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for WriteJointPublicKey {
    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut eg = {
            let csprng = subcommand_helper
                .build_csprng()?
                .write_str("WriteJointPublicKey")
                .finish();
            Eg::from_csprng(csprng)
        };
        let eg = &mut eg;

        {
            //? TODO: Do we need a command line arg to specify the election parameters source?
            let _election_parameters =
                load_election_parameters(eg, &subcommand_helper.artifacts_dir)?;

            //? TODO: Do we need a command line arg to specify all the guardian public key source files?
            let _guardian_public_keys =
                load_all_guardian_public_keys(eg, &subcommand_helper.artifacts_dir)?;
        }

        let joint_public_key = JointPublicKey::get_or_compute(eg)?;

        let (mut stdiowrite, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
            self.out_file.as_ref(),
            Some(&ArtifactFile::JointPublicKey),
        )?;

        joint_public_key
            .to_stdiowrite_pretty(stdiowrite.as_mut())
            .with_context(|| format!("Writing joint election public key to: {}", path.display()))?;

        drop(stdiowrite);

        println!("Wrote joint election public key to: {}", path.display());

        Ok(())
    }
}
