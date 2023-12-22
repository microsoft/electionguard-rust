// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{Context, Result};

use eg::{joint_election_public_key::JointElectionPublicKey, serialize::SerializablePretty};

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{load_all_guardian_public_keys, load_election_parameters},
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct WriteJointElectionPublicKey {
    //? TODO do we need to be able to specify a file for every guardian public key?
    /* */
    /// File to which to write the election public key.
    /// Default is in the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for WriteJointElectionPublicKey {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng(b"WriteHashes")?;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters =
            load_election_parameters(&subcommand_helper.artifacts_dir, &mut csprng)?;

        //? TODO: Do we need a command line arg to specify all the guardian public key source files?
        let guardian_public_keys =
            load_all_guardian_public_keys(&subcommand_helper.artifacts_dir, &election_parameters)?;

        let joint_election_public_key =
            JointElectionPublicKey::compute(&election_parameters, guardian_public_keys.as_slice())?;

        let (mut stdiowrite, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(&self.out_file, Some(ArtifactFile::JointElectionPublicKey))?;

        joint_election_public_key
            .to_stdiowrite(stdiowrite.as_mut())
            .with_context(|| format!("Writing joint election public key to: {}", path.display()))?;

        drop(stdiowrite);

        eprintln!("Wrote joint election public key to: {}", path.display());

        Ok(())
    }
}
