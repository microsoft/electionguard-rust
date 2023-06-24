// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::{
    artifacts_dir::ArtifactFile, common_utils::load_guardian_secret_key,
    subcommand_helper::SubcommandHelper, subcommands::Subcommand,
};

/// A subcommand that does nothing. For a default value.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct GuardianSecretKeyWritePublicKey {
    /// Guardian number, 1 <= i <= n.
    #[arg(long)]
    i: Option<u16>,

    /// File containing the guardian's secret key.
    /// Default is to look in the artifacts dir, if --i is provided.
    #[arg(long)]
    secret_key_in: Option<PathBuf>,

    /// File to which to write the guardian's public key.
    /// Default is in the artifacts dir, based on the guardian number from the secret key file.
    /// If "-", write to stdout.
    #[arg(long)]
    public_key_out: Option<PathBuf>,
}

impl Subcommand for GuardianSecretKeyWritePublicKey {
    fn uses_csprng(&self) -> bool {
        false
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        if self.secret_key_in.is_none() && self.i.is_none() {
            bail!("Specify at least one of --i or --secret-key-in");
        }

        let guardian_secret_key = load_guardian_secret_key(
            self.i,
            &self.secret_key_in,
            &subcommand_helper.artifacts_dir,
        )?;

        let public_key = guardian_secret_key.make_public_key();

        subcommand_helper.artifacts_dir.out_file_write(
            &self.public_key_out,
            ArtifactFile::GuardianPublicKey(guardian_secret_key.i),
            format!("public key for guardian {}", guardian_secret_key.i).as_str(),
            public_key.to_json().as_bytes(),
        )
    }
}
