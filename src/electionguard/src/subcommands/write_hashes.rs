// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::Result;

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
                load_guardian_public_key(Some(i), &None, &subcommand_helper.artifacts_dir).unwrap()
            })
            .collect::<Vec<_>>();

        let jepk = load_joint_election_public_key(&None, &subcommand_helper.artifacts_dir)?;
        // let capital_k_i = CoefficientCommitments(
        //     guardian_public_keys
        //         .iter()
        //         .flat_map(|k| k.coefficient_commitments().0.clone())
        //         .collect(),
        // );

        let hashes = Hashes::new(&election_parameters, &election_manifest);
        subcommand_helper
            .artifacts_dir
            .out_file_write(
                &self.out_file,
                ArtifactFile::Hashes,
                "hashes",
                hashes.to_json().as_bytes(),
            )
            .unwrap();

        if self.extended {
            let hashes_ext =
                HashesExt::new(&election_parameters, &hashes, &jepk, &guardian_public_keys);
            subcommand_helper
                .artifacts_dir
                .out_file_write(
                    &self.out_file,
                    ArtifactFile::HashesExt,
                    "hashes (extended)",
                    hashes_ext.to_json().as_bytes(),
                )
                .unwrap();
        }

        Ok(())
    }
}
