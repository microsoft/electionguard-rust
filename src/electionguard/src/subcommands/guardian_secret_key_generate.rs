// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{ops::DerefMut, path::PathBuf};

use anyhow::{bail, Context, Result};

use eg::{
    guardian::{GuardianIndex, GuardianKeyPurpose},
    guardian_secret_key::GuardianSecretKey,
    serializable::SerializablePretty,
    eg::Eg,
};

use crate::{
    artifacts_dir::ArtifactFile, common_utils::load_election_parameters,
    subcommand_helper::SubcommandHelper, subcommands::Subcommand,
};

#[derive(clap::Args, Debug)]
pub(crate) struct GuardianSecretKeyGenerate {
    /// Guardian number, 1 <= i <= [`VaryingParameters::n`].
    #[arg(long)]
    i: GuardianIndex,

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
    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut eg = {
            let csprng = subcommand_helper
                .build_csprng()?
                .write_str("GuardianSecretKeyGenerate")
                .finish();
            Eg::from_csprng(csprng)
        };
        let eg = &mut eg;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters =
            load_election_parameters(eg, &subcommand_helper.artifacts_dir)?;

        let varying_parameters = &election_parameters.varying_parameters();

        #[allow(clippy::nonminimal_bool)]
        if !(self.i <= varying_parameters.n) {
            bail!(
                "Guardian number {} must be less than or equal to n = {} from election parameters",
                self.i,
                varying_parameters.n
            );
        }

        let name: String = self.name.clone().unwrap_or_default();

        let secret_key = GuardianSecretKey::generate(
            &election_parameters,
            self.i,
            name,
            GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
            eg.csrng(),
        );

        let (mut stdiowrite, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
            self.secret_key_out_file.as_ref(),
            Some(&ArtifactFile::GuardianSecretKey(self.i)),
        )?;

        let description = format!("secret key for guardian {} to: {}", self.i, path.display());

        secret_key
            .to_stdiowrite_pretty(stdiowrite.as_mut())
            .with_context(|| format!("Writing {description}"))?;

        drop(stdiowrite);

        eprintln!("Wrote {description}");

        Ok(())
    }
}
