// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

mod guardian_secret_key_generate;
//? TODO guardian_secret_key_write_interguardian_share;
mod guardian_secret_key_write_public_key;
mod none;
//? TODO #preencrypted_ballot# mod preencrypted_ballot_generate;
//? TODO #preencrypted_ballot# mod preencrypted_ballot_record;
mod verify_standard_parameters;
mod voter_write_confirmation_code;
mod write_hashes;
//? mod write_extended_base_hash;
//? mod write_joint_public_key;
mod write_manifest;
mod write_parameters;
mod write_pre_voting_data;
mod write_random_seed;

#[cfg(feature = "eg-allow-test-data-generation")]
mod generate_random_voter_selections;

mod create_ballot_from_voter_selections;

use anyhow::Result;

use crate::subcommand_helper::SubcommandHelper;

/// Trait to be implemented by each Subcommand enum variant data type.
pub(crate) trait Subcommand {
    // Call to perform the subcommand.
    fn do_it(&mut self, subcommand_info: &mut SubcommandHelper) -> Result<()>;
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Subcommands {
    /// A subcommand that does nothing. For a default value.
    #[clap(skip)]
    None(crate::subcommands::none::None),

    /// Writes some random seed data to an artifact file.
    /// Future commands will use this seed to make their operation deterministic.
    WriteInsecureDeterministicSeedData(
        crate::subcommands::write_random_seed::WriteInsecureDeterministicSeedData,
    ),

    /// Verify standard parameters. Primarily for testing.
    VerifyStandardParameters(
        crate::subcommands::verify_standard_parameters::VerifyStandardParameters,
    ),

    /// Write the election parameters to a file.
    WriteParameters(crate::subcommands::write_parameters::WriteParameters),

    /// Write the election manifest to a file.
    WriteManifest(crate::subcommands::write_manifest::WriteManifest),

    /// Write the hashes to a file.
    WriteHashes(crate::subcommands::write_hashes::WriteHashes),

    /// Generate a guardian secret key.
    GuardianSecretKeyGenerate(
        crate::subcommands::guardian_secret_key_generate::GuardianSecretKeyGenerate,
    ),

    /// Write a guardian public key from a guardian secret key.
    GuardianSecretKeyWritePublicKey(
        crate::subcommands::guardian_secret_key_write_public_key::GuardianSecretKeyWritePublicKey,
    ),

    //? /// Compute the joint election public key from the guardian public keys and write it to a file.
    //? WriteJointPublicKey(
    //?     crate::subcommands::write_joint_public_key::WriteJointPublicKey,
    //? ),

    //? /// Write the extended hash to a file.
    //? WriteExtendedBaseHash(crate::subcommands::write_extended_base_hash::WriteExtendedBaseHash),
    /// Write the pre voting data to a file.
    WritePreVotingData(crate::subcommands::write_pre_voting_data::WritePreVotingData),

    /// Write random ballot selections to a file for testing.
    #[cfg(feature = "eg-allow-test-data-generation")]
    GenerateRandomVoterSelections(
        crate::subcommands::generate_random_voter_selections::GenerateRandomVoterSelections,
    ),

    /// Produce a ballot from voter selections.
    CreateBallotFromVoterSelections(
        crate::subcommands::create_ballot_from_voter_selections::CreateBallotFromVoterSelections,
    ),
    //? TODO /// Write the confirmation QR code for a voter.
    // VoterWriteConfirmationCode(
    //     crate::subcommands::voter_write_confirmation_code::VoterWriteConfirmationCode,
    // ),

    //? TODO #preencrypted_ballot#
    // /// Generate an inter-Guardian share of the guardian secret key.
    // GuardianSecretKeyWriteInterGuardianShare(crate::subcommands::guardian_secret_key_write_interguardian_share::GuardianSecretKeyWriteInterGuardianShare),
    //
    // /// Generate pre-encrypted ballots.
    // PreEncryptedBallotGenerate(
    //     crate::subcommands::preencrypted_ballot_generate::PreEncryptedBallotGenerate,
    // ),
    //
    // /// Record voter selections for pre-encrypted ballots.
    // PreEncryptedBallotRecord(
    //     crate::subcommands::preencrypted_ballot_record::PreEncryptedBallotRecord,
    // ),
}

impl Default for Subcommands {
    fn default() -> Self {
        Subcommands::None(Default::default())
    }
}

impl<'a> From<&'a mut Subcommands> for &'a mut dyn Subcommand {
    fn from(subcommands: &'a mut Subcommands) -> Self {
        use Subcommands::*;
        match subcommands {
            None(a) => a,
            WriteInsecureDeterministicSeedData(a) => a,
            VerifyStandardParameters(a) => a,
            WriteParameters(a) => a,
            WriteManifest(a) => a,
            WriteHashes(a) => a,
            GuardianSecretKeyGenerate(a) => a,
            GuardianSecretKeyWritePublicKey(a) => a,
            //TODO GuardianSecretKeyWriteInterGuardianShare(a) => a,
            //? WriteJointPublicKey(a) => a,
            //? WriteExtendedBaseHash(a) => a,
            WritePreVotingData(a) => a,

            #[cfg(feature = "eg-allow-test-data-generation")]
            GenerateRandomVoterSelections(a) => a,

            CreateBallotFromVoterSelections(a) => a,
            //? TODO VoterWriteConfirmationCode(a) => a,
            //? TODO #preencrypted_ballot# PreEncryptedBallotGenerate(a) => a,
            //? TODO #preencrypted_ballot# PreEncryptedBallotRecord(a) => a,
        }
    }
}
