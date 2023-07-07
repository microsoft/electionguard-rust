// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::Result;

use eg::{
    ballot::BallotStyle, device::Device, election_record::ElectionRecordHeader, hash::HValue,
};
use preencrypted::{
    ballot::{BallotPreEncrypted, BallotSelections},
    ballot_recording_tool::BallotRecordingTool,
};
use verifier::Verifier;
// use voter::{ballot::BallotSelections, verifier::Verifier};

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{
        load_election_parameters, load_hashes, load_hashes_ext, load_joint_election_public_key,
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
        let hashes = load_hashes(&subcommand_helper.artifacts_dir)?;
        let hashes_ext = load_hashes_ext(&subcommand_helper.artifacts_dir)?;
        let jepk =
            load_joint_election_public_key(&subcommand_helper.artifacts_dir, &election_parameters)?;

        let record_header = ElectionRecordHeader::new(
            election_manifest,
            election_parameters.clone(),
            hashes,
            hashes_ext,
            jepk,
        );
        let device = Device::new(&"Ballot Recording Tool".to_string(), record_header.clone());
        let tool = BallotRecordingTool::new(record_header.clone(), BallotStyle(vec![]));
        let verifier = Verifier::new(record_header.clone());

        let codes = {
            let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                &None,
                Some(ArtifactFile::PreEncryptedBallotMetadata(self.tag)),
            )?;
            tool.metadata_from_stdioread(&mut stdioread)?
        };

        for b_idx in 1..codes.len() {
            let pre_encrypted_ballot = {
                let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                    &None,
                    Some(ArtifactFile::PreEncryptedBallots(self.tag, codes[b_idx])),
                )?;
                BallotPreEncrypted::from_stdioread(&mut stdioread)?
            };

            let nonce = {
                let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                    &None,
                    Some(ArtifactFile::PreEncryptedBallotNonces(
                        self.tag,
                        codes[b_idx],
                    )),
                )?;
                HValue::from_stdioread(&mut stdioread)?
            };

            let (regenerated_ballot, matched) =
                tool.regenerate_and_match(&pre_encrypted_ballot, &nonce);
            assert!(matched);

            if matched {
                let regenerated_ballot = regenerated_ballot.unwrap();
                let voter_ballot =
                    BallotSelections::new_pick_random(&record_header.manifest, &mut csprng);
                let encrypted_ballot =
                    regenerated_ballot.finalize(&device, &mut csprng, &voter_ballot);

                assert!(verifier.verify_ballot_validity(&encrypted_ballot));
            } else {
                eprintln!(
                    "Regenerated ballot with nonce {} does not match ballot {}",
                    nonce, b_idx
                );
            }
            // encrypted_ballot.confirmation_code_qr(&path.join(self.tag.as_str()));

            // encrypted_ballot.verification_code_qr(
            //     &voter_ballot,
            //     ballots.primary_nonces[b_idx].as_ref(),
            //     &path.join(self.tag.as_str()),
            // );
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
