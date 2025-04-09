// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use eg::{
    eg::Eg,
    election_parameters::ElectionParameters,
    guardian::GuardianIndex,
    serializable::SerializablePretty, // standard_parameters::STANDARD_PARAMETERS,
    varying_parameters::VaryingParameters,
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

impl From<BallotChaining> for eg::varying_parameters::BallotChaining {
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
    #[arg(long, default_value(""))]
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
    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let eg = subcommand_helper.get_eg("WriteParameters")?;
        let _eg = eg.as_ref();
        anyhow::bail!("TODO: finish implementing WriteParameters");

        /*
        // eprint!("Initializing standard parameters...");
        let fixed_parameters = STANDARD_PARAMETERS.clone();
        // println!("Done.");

        let varying_parameters = VaryingParameters {
            n: self.n,
            k: self.k,
            date: self.date.to_owned(),
            info: self.info.clone(),
            ballot_chaining: self.ballot_chaining.into(),
        };

        let election_parameters = ElectionParameters {
            fixed_parameters,
            varying_parameters,
        };

        let (mut stdiowrite, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
            self.out_file.as_ref(),
            Some(&ArtifactFile::ElectionParameters),
        )?;

        election_parameters
            .to_stdiowrite_pretty(stdiowrite.as_mut())
            .with_context(|| format!("Writing election parameters to: {}", path.display()))?;

        drop(stdiowrite);

        println!("Wrote election parameters to: {}", path.display());

        Ok(())
        // */
    }
}
