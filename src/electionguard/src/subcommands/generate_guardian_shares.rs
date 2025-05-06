// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{collections::HashMap, path::PathBuf};

use crate::{
    artifacts_dir::{ArtifactFile, ArtifactsDir},
    subcommand_helper::SubcommandHelper,
    Subcommand,
};
use anyhow::{bail, Result};
use clap::Args;
use eg::{
    election_manifest::ElectionManifest, election_parameters::ElectionParameters,
    example_election_manifest::example_election_manifest_small,
    example_election_parameters::example_election_parameters, guardian::shares_to_json,
    hashes::Hashes, key::PublicKey,
};
use util::file::read_path;

#[derive(Args, Debug)]
pub(crate) struct GenerateGuardianShares {
    /// Sequence order
    #[arg(long)]
    i: i32,

    /// File from which to read the election manifest.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Use the example election manifest.
    #[arg(long)]
    example_manifest: bool,

    /// Path to election data store
    #[arg(long, default_value_t = String::from("data"))]
    data: String,
}

impl Subcommand for GenerateGuardianShares {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut eg = {
            let csprng = subcommand_helper
                .build_csprng()?
                .write_str("GenerateGuardianShares")
                .finish();
            Eg::from_csprng(csprng)
        };
        let eg = &mut eg;

        use eg::guardian::Guardian;

        if self.example_manifest && self.election_manifest().is_some() {
            anyhow::bail!("Specify either --example-manifest or --manifest, but not both.");
        }

        let election_parameters: ElectionParameters;
        let election_manifest: ElectionManifest;

        if self.example_manifest {
            election_parameters = example_election_parameters()?;
            election_manifest = example_election_manifest_small();
        } else {
            return Err(anyhow::anyhow!("Not implemented yet"));
        }

        let hashes = Hashes::new(&election_parameters, &election_manifest);

        assert!(self.i != 0 && self.i as u16 <= election_parameters.varying_parameters().n());

        // Read guardian private data
        let guardian = Guardian::from_json(
            &String::from_utf8(read_path(
                &subcommand_helper
                    .artifacts_dir
                    .path(ArtifactFile::GuardianPrivateData(self.i as u16)),
            ))
            .unwrap(),
        );
        assert!(guardian.i == self.i as usize);

        let mut public_keys = <HashMap<u16, PublicKey>>::new();

        // Read public keys associated with other guardians
        for l in 1..election_parameters.varying_parameters().n() + 1 {
            if guardian.i != l as usize {
                // let their_artifacts = ArtifactsDir::new(
                //     subcommand_helper
                //         .artifacts_dir
                //         .dir_path
                //         .parent()
                //         .unwrap()
                //         .join(format!("{}", l)),
                // )
                // .unwrap();

                public_keys.insert(
                    l,
                    PublicKey::from_json(
                        &String::from_utf8(read_path(
                            &subcommand_helper
                                .artifacts_dir
                                .path(ArtifactFile::GuardianPublicKey(l as u16, Canonical)),
                        ))
                        .unwrap(),
                    ),
                );
            }
        }

        // let mut shares = Vec::with_capacity(election_parameters.varying_parameters.n as usize - 1);
        // Generate an inter-Guardian share for each other guardian
        for l in 1..election_parameters.varying_parameters().n() + 1 {
            if guardian.i != l as usize {
                let share = guardian.share_for(
                    csprng,
                    &election_parameters,
                    &hashes.h_p,
                    l as usize,
                    &public_keys[&l],
                );

                // subcommand_helper.artifacts_dir.out_file_write(
                //     &Some(
                //         subcommand_helper
                //             .artifacts_dir
                //             .path(ArtifactFile::InterguardianShares(guardian.i as u16, l)),
                //     ),
                //     ArtifactFile::InterguardianShares(ArtifactFile::InterguardianShares(
                //         guardian.i as u16,
                //         l,
                //     )),
                //     "guardian inter-Guardian shares",
                //     share.as_bytes(),
                // );
            }
        }

        Ok(())
    }
}
