// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::Result;

use eg::{device::Device, election_record::ElectionRecordHeader, hash::HValue};
use preencrypted::{ballot::BallotPreEncrypted, ballot_recording_tool::BallotRecordingTool};
use voter::ballot::BallotSelections;

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{
        load_election_parameters, load_hashes, load_joint_election_public_key,
        ElectionManifestSource,
    },
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

/// Generate a guardian secret key and public key.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct PreEncryptedBallotRecord {
    /// Number of ballots to generate
    #[arg(short, long, default_value_t = 1)]
    num_ballots: usize,

    // Tag for ballot verification
    #[arg(short, long, default_value_t = 0)]
    tag: u128,
}

impl Subcommand for PreEncryptedBallotRecord {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng =
            subcommand_helper.get_csprng(format!("PreEncryptedBallotGenerate").as_bytes())?;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters =
            load_election_parameters(&subcommand_helper.artifacts_dir, &mut csprng)?;

        //? TODO: Do we need a command line arg to specify the election manifest source?
        let election_manifest_source =
            ElectionManifestSource::ArtifactFileElectionManifestCanonical;
        let election_manifest =
            election_manifest_source.load_election_manifest(&subcommand_helper.artifacts_dir)?;
        let (hashes, hashes_ext) = load_hashes(&None, &None, &subcommand_helper.artifacts_dir)?;
        let jepk = load_joint_election_public_key(&None, &subcommand_helper.artifacts_dir)?;

        let record_header = ElectionRecordHeader::new(
            election_manifest,
            election_parameters,
            hashes,
            hashes_ext,
            jepk,
        );
        let device = Device::new(&"Ballot Recording Tool".to_string(), record_header.clone());

        for b_idx in 1..self.num_ballots {
            let mut pre_encrypted_ballot = {
                let (mut io_read, _) = subcommand_helper.artifacts_dir.in_file_read(
                    &None,
                    Some(ArtifactFile::PreEncryptedBallots(self.tag, b_idx as u128)),
                )?;
                BallotPreEncrypted::from_reader(&mut io_read)?
            };

            let nonce = {
                let (mut io_read, _) = subcommand_helper.artifacts_dir.in_file_read(
                    &None,
                    Some(ArtifactFile::PreEncryptedBallotNonces(
                        self.tag,
                        b_idx as u128,
                    )),
                )?;
                HValue::from_reader(&mut io_read)?
            };

            // let pre_encrypted_ballot = &mut ballots.ballots[b_idx];
            assert!(BallotRecordingTool::verify_ballot(
                &device.header,
                &pre_encrypted_ballot,
                &nonce
            ));

            BallotRecordingTool::regenerate_nonces(&device, &mut pre_encrypted_ballot, &nonce);

            let voter_ballot =
                BallotSelections::new_pick_random(&device.header.manifest, &mut csprng);

            let encrypted_ballot =
                pre_encrypted_ballot.finalize(&device, &mut csprng, &voter_ballot);

            // encrypted_ballot.confirmation_code_qr(&path.join(self.tag.as_str()));

            // encrypted_ballot.verification_code_qr(
            //     &voter_ballot,
            //     ballots.primary_nonces[b_idx].as_ref(),
            //     &path.join(self.tag.as_str()),
            // );

            BallotRecordingTool::verify_ballot_proofs(&device, &encrypted_ballot);
        }

        Ok(())

        // TODO: Encrypt them
        // subcommand_helper.artifacts_dir.out_file_write(
        //     &None,
        //     ArtifactFile::PreEncryptedBallotNonces(label as u128),
        //     format!("pre-encrypted ballot nonces").as_str(),
        //     format!("{:?}", &vec![confirmation_codes, primary_nonces.clone()]).as_bytes(),
        // )
    }
}
