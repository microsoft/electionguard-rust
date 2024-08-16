// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

mod guardian_secret_key_generate;
//? TODO #preencrypted_ballot# mod guardian_secret_key_write_encrypted_share;
mod guardian_secret_key_write_public_key;
mod none;
//? TODO #preencrypted_ballot# mod preencrypted_ballot_generate;
//? TODO #preencrypted_ballot# mod preencrypted_ballot_record;
mod verify_standard_parameters;
mod voter_write_confirmation_code;
mod write_hashes;
mod write_hashes_ext;
mod write_joint_election_public_key;
mod write_manifest;
mod write_parameters;
mod write_pre_voting_data;
mod write_random_seed;

#[cfg(feature = "eg-test-data-generation")]
mod voter_write_random_selections;

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

    /// Compute the joint election public key from the guardian public keys and write it to a file.
    WriteJointElectionPublicKey(
        crate::subcommands::write_joint_election_public_key::WriteJointElectionPublicKey,
    ),

    /// Write the extended hash to a file.
    WriteHashesExt(crate::subcommands::write_hashes_ext::WriteHashesExt),

    /// Write the pre voting data to a file.
    WritePreVotingData(crate::subcommands::write_pre_voting_data::WritePreVotingData),

    /// Write random ballot selections to a file for testing.
    #[cfg(feature = "eg-test-data-generation")]
    VoterWriteRandomSelections(
        crate::subcommands::voter_write_random_selections::VoterWriteRandomSelection,
    ),

    /// Write the confirmation QR code for a voter.
    VoterWriteConfirmationCode(
        crate::subcommands::voter_write_confirmation_code::VoterWriteConfirmationCode,
    ),
    //? TODO #preencrypted_ballot#
    // /// Generate an encrypted share of the guardian secret key.
    // GuardianSecretKeyWriteEncryptedShare(crate::subcommands::guardian_secret_key_write_encrypted_share::GuardianSecretKeyWriteEncryptedShare),
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
            WriteRandomSeed(a) => a,
            VerifyStandardParameters(a) => a,
            WriteParameters(a) => a,
            WriteManifest(a) => a,
            WriteHashes(a) => a,
            GuardianSecretKeyGenerate(a) => a,
            GuardianSecretKeyWritePublicKey(a) => a,
            //TODO GuardianSecretKeyWriteEncryptedShare(a) => a,
            WriteJointElectionPublicKey(a) => a,
            WriteHashesExt(a) => a,
            WritePreVotingData(a) => a,

            #[cfg(feature = "eg-test-data-generation")]
            VoterWriteRandomSelections(a) => a,

            VoterWriteConfirmationCode(a) => a,
            //? TODO #preencrypted_ballot# PreEncryptedBallotGenerate(a) => a,
            //? TODO #preencrypted_ballot# PreEncryptedBallotRecord(a) => a,
        }
    }
}
