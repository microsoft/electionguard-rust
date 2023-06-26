// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use eg::{ballot::BallotStyle, device::Device, election_record::ElectionRecordHeader};
use preencrypted::ballot_encrypting_tool::BallotEncryptingTool;
use util::file::create_path;

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
pub(crate) struct PreEncryptedBallotGenerate {
    /// Number of ballots to generate
    #[arg(short, long, default_value_t = 1)]
    num_ballots: usize,

    /// Whether to encrypt the nonce with the election public key
    #[arg(short, long, default_value_t = false)]
    encrypt_nonce: bool,
}

impl Subcommand for PreEncryptedBallotGenerate {
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

        // Write election record header to file
        subcommand_helper
            .artifacts_dir
            .out_file_write(
                &Some(
                    subcommand_helper
                        .artifacts_dir
                        .path(ArtifactFile::ElectionRecordHeader),
                ),
                ArtifactFile::ElectionRecordHeader,
                "Election Record Header",
                record_header.to_canonical_bytes().as_slice(),
            )
            .unwrap();

        let device = Device::new(&"Ballot Encrypting Tool".to_string(), record_header.clone());

        let tool =
            BallotEncryptingTool::new(device.header, BallotStyle(vec!["".to_string()]), None);

        let (ballots, primary_nonces) = tool.generate_ballots(&mut csprng, self.num_ballots);

        let label = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        create_path(
            &subcommand_helper
                .artifacts_dir
                .dir_path
                .join(format!("pre_encrypted_ballots/{label}")),
        );

        let mut confirmation_codes = Vec::with_capacity(self.num_ballots);
        for b_idx in 0..self.num_ballots {
            // BallotEncryptingTool::print_ballot(
            //     b_idx + 1,
            //     &ballots[b_idx],
            //     &primary_nonces[b_idx].to_string(),
            // );
            confirmation_codes.push(ballots[b_idx].confirmation_code);
            subcommand_helper.artifacts_dir.out_file_write(
                &None,
                ArtifactFile::PreEncryptedBallots(label as u128, b_idx as u128 + 1),
                format!("pre-encrypted ballot #{}", b_idx + 1).as_str(),
                ballots[b_idx].to_json().as_bytes(),
            )?;

            subcommand_helper.artifacts_dir.out_file_write(
                &None,
                ArtifactFile::PreEncryptedBallotNonces(label as u128, b_idx as u128 + 1),
                format!("pre-encrypted ballot nonce #{}", b_idx + 1).as_str(),
                primary_nonces[b_idx].to_json().as_bytes(),
            )?;
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
