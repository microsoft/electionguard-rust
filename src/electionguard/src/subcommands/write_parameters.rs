// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{Context, Result};

use eg::{
    election_parameters::ElectionParameters, guardian::GuardianIndex,
    standard_parameters::STANDARD_PARAMETERS, varying_parameters::VaryingParameters,
};

use crate::{
    artifacts_dir::ArtifactFile, subcommand_helper::SubcommandHelper, subcommands::Subcommand,
};

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BallotChaining {
    Prohibited,
    Allowed,
    Required,
}

impl std::convert::From<BallotChaining> for eg::varying_parameters::BallotChaining {
    fn from(value: BallotChaining) -> Self {
        use eg::varying_parameters::BallotChaining as EgBallotChaining;
        match value {
            BallotChaining::Prohibited => EgBallotChaining::Prohibited,
            BallotChaining::Allowed => EgBallotChaining::Allowed,
            BallotChaining::Required => EgBallotChaining::Required,
        }
    }
}

#[derive(clap::Args, Debug)]
pub(crate) struct WriteParameters {
    /// Number of guardians.
    #[arg(long)]
    n: GuardianIndex,

    /// Decryption quorum threshold value.
    #[arg(long)]
    k: GuardianIndex,

    /// Date string.
    #[arg(long)]
    date: String,

    // Jurisdictional information string.
    #[arg(long)]
    info: String,

    // Ballot chaining.
    #[arg(long)]
    ballot_chaining: BallotChaining,

    /// File to which to write the election parameters.
    /// Default is the election parameters file in the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for WriteParameters {
    fn uses_csprng(&self) -> bool {
        false
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        eprint!("Initializing standard parameters...");
        let fixed_parameters = STANDARD_PARAMETERS.clone();
        eprintln!("Done.");

        let varying_parameters = VaryingParameters {
            n: self.n,
            k: self.k,
            date: self.date.clone(),
            info: self.info.clone(),
            ballot_chaining: self.ballot_chaining.into(),
        };

        let election_parameters = ElectionParameters {
            fixed_parameters,
            varying_parameters,
        };

        let (mut stdiowrite, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(&self.out_file, Some(ArtifactFile::ElectionParameters))?;

        election_parameters
            .to_stdiowrite(stdiowrite.as_mut())
            .with_context(|| format!("Writing election parameters to: {}", path.display()))?;

        drop(stdiowrite);

        eprintln!("Wrote election parameters to: {}", path.display());

        Ok(())
    }
}
