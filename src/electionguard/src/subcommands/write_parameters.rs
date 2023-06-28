// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{Context, Result};

use eg::{
    election_parameters::ElectionParameters, standard_parameters::STANDARD_PARAMETERS,
    varying_parameters::VaryingParameters,
};

use crate::{
    artifacts_dir::ArtifactFile, subcommand_helper::SubcommandHelper, subcommands::Subcommand,
};

/// Writes the election parameters to a file.
/// The fixed parameters are `eg::standard_parameters::STANDARD_PARAMETERS`.
/// The varying parameters are specified by the user.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct WriteParameters {
    /// Number of guardians.
    #[arg(long)]
    n: u16,

    /// Decryption quorum threshold value.
    #[arg(long)]
    k: u16,

    /// Date string.
    #[arg(long)]
    date: String,

    // Jurisdictional information string.
    #[arg(long)]
    info: String,

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
        };

        let election_parameters = ElectionParameters {
            fixed_parameters,
            varying_parameters,
        };

        let (mut bx_write, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(&self.out_file, Some(ArtifactFile::ElectionParameters))?;

        election_parameters
            .to_stdiowrite(bx_write.as_mut())
            .with_context(|| format!("Writing election parameters to: {}", path.display()))?;

        drop(bx_write);

        eprintln!("Wrote election parameters to: {}", path.display());

        Ok(())
    }
}
