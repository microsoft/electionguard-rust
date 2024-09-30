// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use eg::{guardian::GuardianIndex, serializable::{SerializableCanonical, SerializablePretty}};

use crate::{
    artifacts_dir::{ArtifactFile, CanonicalPretty},
    common_utils::{load_election_parameters, load_guardian_secret_key},
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct GuardianSecretKeyWritePublicKey {
    /// Guardian number, 1 <= i <= n.
    #[arg(long)]
    i: Option<GuardianIndex>,

    /// File containing the guardian's secret key.
    /// Default is to look in the artifacts dir, if --i is provided.
    #[arg(long)]
    secret_key_in: Option<PathBuf>,

    /// File to which to write the guardian's public key.
    /// Default is in the artifacts dir, based on the guardian number from the secret key file.
    /// If "-", write to stdout.
    #[arg(long)]
    public_key_out: Option<PathBuf>,

    /// Write the canonical form of the public key.
    #[arg(long)]
    pub canonical: bool,
}

impl Subcommand for GuardianSecretKeyWritePublicKey {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper
            .get_csprng(format!("GuardianSecretKeyWritePublicKey({:?})", self.i).as_bytes())?;

        if self.secret_key_in.is_none() && self.i.is_none() {
            bail!("Specify at least one of --i or --secret-key-in");
        }

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters =
            load_election_parameters(&subcommand_helper.artifacts_dir, &mut csprng)?;

        let guardian_secret_key = load_guardian_secret_key(
            self.i,
            &self.secret_key_in,
            &subcommand_helper.artifacts_dir,
            &election_parameters,
        )?;

        let i = guardian_secret_key.i;

        let public_key = guardian_secret_key.make_public_key();

        let canonical_pretty = if self.canonical { CanonicalPretty::Canonical } else { CanonicalPretty::Pretty };

        let (mut stdiowrite, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
            &self.public_key_out,
            Some(ArtifactFile::GuardianPublicKey(i, canonical_pretty)),
        )?;

        let result = if self.canonical {
            public_key.to_stdiowrite_canonical(stdiowrite.as_mut())
        } else {
            public_key.to_stdiowrite_pretty(stdiowrite.as_mut())
        };
        result.with_context(|| {
            format!("Writing public key for guardian {i} to: {}", path.display())
        })?;

        drop(stdiowrite);

        eprintln!("Wrote public key for guardian {i} to: {}", path.display());

        Ok(())
    }
}
