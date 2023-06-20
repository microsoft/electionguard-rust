// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

mod generate_guardian_key;
mod generate_guardian_shares;
mod none;
mod preencrypted_ballots;
mod verify_guardian_proof;
mod verify_guardian_shares;
mod verify_standard_parameters;
mod write_hashes;
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

    /// Write the election manifest to a file.
    WriteManifest(crate::subcommands::write_manifest::WriteManifest),

    /// Write the election parameters to a file.
    WriteParameters(crate::subcommands::write_parameters::WriteParameters),

    /// Write the hashes to a file.
    WriteHashes(crate::subcommands::write_hashes::WriteHashes),

    /// Generate a key pair for a guardian.
    GenerateGuardianKey(crate::subcommands::generate_guardian_key::GenerateGuardianKey),

    /// Generate secret shares and proofs for a guardian.
    GenerateGuardianShares(crate::subcommands::generate_guardian_shares::GenerateGuardianShares),

    /// Verify secret shares from a guardian.
    VerifyGuardianShares(crate::subcommands::verify_guardian_shares::VerifyGuardianShares),

    /// Verify proof of knowledge from a guardian.
    VerifyGuardianProof(crate::subcommands::verify_guardian_proof::VerifyGuardianProof),

    /// Generate or verify pre-encrypted ballots.
    PreEncryptedBallots(crate::subcommands::preencrypted_ballots::PreEncryptedBallots),
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
            Subcommands::WriteHashes(a) => a,
            Subcommands::GenerateGuardianKey(a) => a,
            Subcommands::PreEncryptedBallots(a) => a,
            Subcommands::GenerateGuardianShares(a) => a,
            Subcommands::VerifyGuardianShares(a) => a,
            Subcommands::VerifyGuardianProof(a) => a,
        }
    }
}
