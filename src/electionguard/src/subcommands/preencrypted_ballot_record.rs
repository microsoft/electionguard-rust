// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{bail, Context, Result};

use eg::{ballot_style::BallotStyle, device::Device, election_record::PreVotingData, hash::HValue};
use preencrypted::{
    ballot::{BallotPreEncrypted, VoterSelection},
    ballot_recording_tool::BallotRecordingTool,
};
use util::file::create_path;
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

/// Record voter selections on a pre-encrypted ballot.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct PreEncryptedBallotRecord {
    /// Number of ballots to verify.
    #[arg(short, long, default_value_t = 1)]
    num_ballots: usize,

    /// Path for voter selections.
    #[arg(short, long)]
    selections_in: u128,

    /// Path for pre-encrypted ballots.
    #[arg(short, long)]
    ballots_in: u128,

    /// The ballot style to verify.
    #[arg(short, long)]
    ballot_style: Option<String>,
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

        let mut ballot_style = BallotStyle::empty();
        match &self.ballot_style {
            None => bail!("Ballot style is required to verify pre-encrypted ballots."),
            Some(bs) => {
                for i in 0..election_manifest.ballot_styles.len() {
                    if election_manifest.ballot_styles[i].label == *bs {
                        ballot_style = election_manifest.ballot_styles[i].clone();
                        break;
                    }
                }
            }
        }

        let hashes = load_hashes(&subcommand_helper.artifacts_dir)?;
        let hashes_ext = load_hashes_ext(&subcommand_helper.artifacts_dir)?;
        let jepk =
            load_joint_election_public_key(&subcommand_helper.artifacts_dir, &election_parameters)?;

        let record_header = PreVotingData::new(
            election_manifest,
            election_parameters.clone(),
            hashes,
            hashes_ext,
            jepk,
        );
        let device = Device::new(&"Ballot Recording Tool".to_string(), record_header.clone());
        let tool = BallotRecordingTool::new(record_header.clone(), ballot_style.clone());
        let verifier = Verifier::new(record_header.clone());

        let codes = {
            let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                &None,
                Some(ArtifactFile::PreEncryptedBallotMetadata(self.ballots_in)),
            )?;
            tool.metadata_from_stdioread(&mut stdioread)?
        };

        create_path(
            &subcommand_helper
                .artifacts_dir
                .dir_path
                .join(format!("record/ballots/{}", self.ballots_in)),
        );

        for b_idx in 1..codes.len() + 1 {
            let pre_encrypted_ballot = {
                let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                    &None,
                    Some(ArtifactFile::PreEncryptedBallot(
                        self.ballots_in,
                        codes[b_idx - 1],
                    )),
                )?;
                BallotPreEncrypted::from_stdioread(&mut stdioread)?
            };

            let nonce = {
                let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                    &None,
                    Some(ArtifactFile::PreEncryptedBallotNonce(
                        self.ballots_in,
                        codes[b_idx - 1],
                    )),
                )?;
                HValue::from_stdioread(&mut stdioread)?
            };

            let (regenerated_ballot, matched) =
                tool.regenerate_and_match(&pre_encrypted_ballot, &ballot_style, &nonce);
            assert!(matched);

            if matched {
                let regenerated_ballot = regenerated_ballot.unwrap();
                let voter_ballot = {
                    let (mut stdioread, _) = subcommand_helper.artifacts_dir.in_file_stdioread(
                        &None,
                        Some(ArtifactFile::VoterSelection(
                            self.selections_in,
                            b_idx as u64,
                        )),
                    )?;

                    VoterSelection::from_stdioread(&mut stdioread)?
                };
                let encrypted_ballot =
                    regenerated_ballot.finalize(&device, &mut csprng, &voter_ballot);

                assert!(verifier.verify_ballot_validity(&encrypted_ballot));

                let (mut bx_write, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
                    &None,
                    Some(ArtifactFile::EncryptedBallot(
                        self.ballots_in,
                        encrypted_ballot.confirmation_code,
                    )),
                )?;

                encrypted_ballot
                    .to_stdiowrite(bx_write.as_mut())
                    .with_context(|| format!("Writing encrypted ballot to: {}", path.display()))?;
                drop(bx_write);
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
