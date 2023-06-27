// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{num::NonZeroU16, path::PathBuf};

use anyhow::Result;

use eg::joint_election_public_key::JointElectionPublicKey;

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{load_election_parameters, load_guardian_public_key},
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

/// Writes the hashes to a file.
/// The election parameters and election manifest are read from the artifacts dir.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct WriteJointElectionPublicKey {
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

        let guardian_public_keys = (1..election_parameters.varying_parameters.n + 1)
            .map(|i| {
                load_guardian_public_key(
                    Some(NonZeroU16::new(i).unwrap()),
                    &None,
                    &subcommand_helper.artifacts_dir,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let jepk = JointElectionPublicKey::compute(
            &election_parameters.fixed_parameters,
            guardian_public_keys.as_slice(),
        );

        subcommand_helper.artifacts_dir.out_file_write(
            &self.out_file,
            ArtifactFile::JointElectionPublicKey,
            "joint election public key",
            jepk.to_json().as_bytes(),
        )
    }
}
