// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use eg::{ballot_style::BallotStyleIndex, device::Device, election_record::PreVotingData};
use preencrypted::ballot_encrypting_tool::BallotEncryptingTool;
use util::file::create_path;

use crate::{
    artifacts_dir::ArtifactFile,
    common_utils::{
        load_election_parameters, load_hashes, load_hashes_ext, load_joint_election_public_key,
        ElectionManifestSource,
    },
    subcommand_helper::SubcommandHelper,
    subcommands::Subcommand,
};

/// Generate a pre-encrypted ballot.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct PreEncryptedBallotGenerate {
    /// Number of ballots to generate.
    #[arg(short, long, default_value_t = 1)]
    num_ballots: usize,

    /// If true, encrypt primary nonce(s) with the election public key.
    #[arg(short, long, default_value_t = false)]
    encrypt_nonce: bool,

    /// 1-index of the ballot style to generate.
    #[arg(short, long, default_value_t = 0)]
    ballot_style_index: u32,
}

impl Subcommand for PreEncryptedBallotGenerate {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng("PreEncryptedBallotGenerate".as_bytes())?;

        //? TODO: Do we need a command line arg to specify the election parameters source?
        let election_parameters =
            load_election_parameters(&subcommand_helper.artifacts_dir, &mut csprng)?;

        //? TODO: Do we need a command line arg to specify the election manifest source?
        let election_manifest_source =
            ElectionManifestSource::ArtifactFileElectionManifestCanonical;
        let election_manifest =
            election_manifest_source.load_election_manifest(&subcommand_helper.artifacts_dir)?;

        if self.ballot_style_index == 0 {
            bail!("Ballot style is required to generate pre-encrypted ballots.");
        }

        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        let ballot_style_index =
            BallotStyleIndex::from_one_based_index(self.ballot_style_index).unwrap();

        let hashes = load_hashes(&subcommand_helper.artifacts_dir)?;
        let hashes_ext = load_hashes_ext(&subcommand_helper.artifacts_dir)?;
        let jepk =
            load_joint_election_public_key(&subcommand_helper.artifacts_dir, &election_parameters)?;

        let pv_data = PreVotingData::new(
            election_manifest,
            election_parameters,
            hashes,
            hashes_ext,
            jepk,
        );

        let (mut bx_write, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(&None, Some(ArtifactFile::ElectionPreVotingData))?;

        pv_data
            .to_stdiowrite(bx_write.as_mut())
            .with_context(|| format!("Writing record header to: {}", path.display()))?;

        drop(bx_write);

        let device = Device::new("Ballot Encrypting Tool", pv_data.clone());

        let tool = BallotEncryptingTool::new(device.header, ballot_style_index, None);

        let (ballots, primary_nonces) = tool.generate_ballots(&mut csprng, self.num_ballots);

        let label = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        create_path(
            &subcommand_helper
                .artifacts_dir
                .dir_path
                .join(format!("pre_encrypted/ballots/{label}")),
        );
        create_path(
            &subcommand_helper
                .artifacts_dir
                .dir_path
                .join(format!("pre_encrypted/nonces/{label}")),
        );

        let mut confirmation_codes = Vec::with_capacity(self.num_ballots);
        for b_idx in 0..self.num_ballots {
            confirmation_codes.push(ballots[b_idx].confirmation_code);

            let (mut bx_write, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
                &None,
                Some(ArtifactFile::PreEncryptedBallot(
                    label as u128,
                    ballots[b_idx].confirmation_code,
                )),
            )?;

            ballots[b_idx]
                .to_stdiowrite(bx_write.as_mut())
                .with_context(|| format!("Writing pre-encrypted ballot to: {}", path.display()))?;

            eprintln!("Wrote pre-encrypted ballot to: {}", path.display());

            drop(bx_write);

            let (mut bx_write, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
                &None,
                Some(ArtifactFile::PreEncryptedBallotNonce(
                    label as u128,
                    ballots[b_idx].confirmation_code,
                )),
            )?;

            primary_nonces[b_idx]
                .to_stdiowrite(bx_write.as_mut())
                .with_context(|| {
                    format!("Writing pre-encrypted ballot nonce to: {}", path.display())
                })?;

            drop(bx_write);
        }

        let (mut bx_write, path) = subcommand_helper.artifacts_dir.out_file_stdiowrite(
            &None,
            Some(ArtifactFile::PreEncryptedBallotMetadata(label as u128)),
        )?;

        tool.metadata_to_stdiowrite(&confirmation_codes, bx_write.as_mut())
            .with_context(|| {
                format!(
                    "Writing pre-encrypted ballot metadata to: {}",
                    path.display()
                )
            })?;

        drop(bx_write);

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
