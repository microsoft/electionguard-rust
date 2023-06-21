// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{bail, Result};

use eg::key::PrivateKey;

use crate::{
    artifacts_dir::ArtifactFile,
    subcommand_helper::SubcommandHelper, subcommands::Subcommand,
    common_utils::load_election_parameters,    
};

/// A subcommand that does nothing. For a default value.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct GuardianKeyGenerate {

    /// Guardian number, 0 <= i < n.
    #[arg(long)]
    i: u16,

    /// Descriptive string for the guardian.
    #[arg(long)]
    name: Option<String>,

    /// File to which to write the public key.
    /// Default is in the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    public_key_out_file: Option<PathBuf>,
    
    /// File to which to write the private key.
    /// Default is in the guardian's dir under the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    private_key_out_file: Option<PathBuf>,
    
}

impl Subcommand for GuardianKeyGenerate {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng(
            format!("GuardianKeyGenerate({})", self.i).as_bytes()
        )?;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters = load_election_parameters(
            &subcommand_helper.artifacts_dir,
            &mut csprng
        )?;

        let varying_parameters = &election_parameters.varying_parameters;

        if !(self.i < varying_parameters.n) {
            bail!("Guardian number {} must be less than n = {} from election parameters",
                self.i, varying_parameters.n
            );
        }

        let private_key = PrivateKey::generate(
            &mut csprng, &election_parameters,
            self.i, self.name.clone());

        subcommand_helper.artifacts_dir.out_file_write(
            &self.private_key_out_file,
            ArtifactFile::GuardianPrivateKey(self.i),
            format!("private key for guardian {}", self.i).as_str(),
            private_key.to_json().as_bytes(),
        )?;

        let public_key = private_key.make_public_key();

        subcommand_helper.artifacts_dir.out_file_write(
            &self.public_key_out_file,
            ArtifactFile::GuardianPublicKey(self.i),
            format!("public key for guardian {}", self.i).as_str(),
            public_key.to_json().as_bytes(),
        )
    }
}
