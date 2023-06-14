// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

mod none;
mod verify_standard_parameters;
mod write_manifest;
mod write_parameters;
mod write_random_seed;

use anyhow::Result;

use crate::subcommand_helper::SubcommandHelper;

/// Trait to be implemented by each Subcommand enum variant data type.
pub(crate) trait Subcommand {
    // If returns `true` the subcommand may use the csprng.
    fn uses_csprng(&self) -> bool;

    // Call to perform the subcommand.
    fn do_it(&mut self, subcommand_info: &mut SubcommandHelper) -> Result<()>;
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Subcommands {
    /// A subcommand that does nothing. For a default value.
    #[clap(skip)]
    None(crate::subcommands::none::None),

    /// Writes a random seed file to the artifacts directory.
    /// Future commands will use this seed to make their operation deterministic.
    WriteRandomSeed(crate::subcommands::write_random_seed::WriteRandomSeed),

    /// Verify standard parameters. Primarily for testing.
    VerifyStandardParameters(
        crate::subcommands::verify_standard_parameters::VerifyStandardParameters,
    ),

    /// Write the manifest to a file.
    WriteManifest(crate::subcommands::write_manifest::WriteManifest),

    /// Write the parameters to a file.
    WriteParameters(crate::subcommands::write_parameters::WriteParameters),
}

impl Default for Subcommands {
    fn default() -> Self {
        Subcommands::None(Default::default())
    }
}

impl<'a> From<&'a mut Subcommands> for &'a mut dyn Subcommand {
    fn from(subcommands: &'a mut Subcommands) -> Self {
        match subcommands {
            Subcommands::None(a) => a,
            Subcommands::WriteRandomSeed(a) => a,
            Subcommands::VerifyStandardParameters(a) => a,
            Subcommands::WriteManifest(a) => a,
            Subcommands::WriteParameters(a) => a,
        }
    }
}
