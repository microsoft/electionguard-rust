// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::num::NonZeroU16;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use eg::guardian_secret_key::GuardianSecretKey;

use crate::{
    artifacts_dir::ArtifactFile, common_utils::load_election_parameters,
    subcommand_helper::SubcommandHelper, subcommands::Subcommand,
};

#[derive(clap::Args, Debug)]
pub(crate) struct GuardianSecretKeyGenerate {
    /// Guardian number, 1 <= i <= n.
    #[arg(long)]
    i: NonZeroU16,

    /// Guardian's name or other short description.
    #[arg(long)]
    name: Option<String>,

    /// File to which to write the guardian's secret key.
    /// Default is in the guardian's dir under the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    secret_key_out_file: Option<PathBuf>,
}

impl Subcommand for GuardianSecretKeyGenerate {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper
            .get_csprng(format!("GuardianSecretKeyGenerate({})", self.i).as_bytes())?;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters =
            load_election_parameters(&subcommand_helper.artifacts_dir, &mut csprng)?;

        let varying_parameters = &election_parameters.varying_parameters;

        #[allow(clippy::nonminimal_bool)]
        if !(self.i.get() <= varying_parameters.n) {
            bail!(
                "Guardian number {} must be less than or equal to n = {} from election parameters",
                self.i,
                varying_parameters.n
            );
        }

        let secret_key = GuardianSecretKey::generate(
            &mut csprng,
            &election_parameters,
            self.i,
            self.name.clone(),
        );

        let (mut stdiowrite, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
            &self.secret_key_out_file,
            Some(ArtifactFile::GuardianSecretKey(self.i)),
        )?;

        let description = format!("secret key for guardian {} to: {}", self.i, path.display());

        secret_key
            .to_stdiowrite(stdiowrite.as_mut())
            .with_context(|| format!("Writing {description}"))?;

        drop(stdiowrite);

        eprintln!("Wrote {description}");

        Ok(())
    }
}
