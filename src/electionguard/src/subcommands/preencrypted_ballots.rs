// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::{Path, PathBuf};

use crate::{
    artifacts_dir::{ArtifactFile, ArtifactsDir},
    subcommand_helper::SubcommandHelper,
    Subcommand,
};
use anyhow::{bail, Result};
use clap::Args;
use eg::{
    ballot::{BallotDecrypted, BallotStyle},
    device::Device,
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    election_record::ElectionRecordHeader,
    example_election_manifest::{example_election_manifest, example_election_manifest_small},
    example_election_parameters::example_election_parameters,
    guardian::aggregate_public_keys,
    hashes::Hashes,
    key::PublicKey,
    nizk::ProofGuardian,
};
use preencrypted::{
    ballot_encrypting_tool::BallotEncryptingTool, ballot_list::BallotListPreEncrypted,
    ballot_recording_tool::BallotRecordingTool,
};
use util::{file::read_path, logging::Logging};

#[derive(Args, Debug)]
pub(crate) struct PreEncryptedBallots {
    /// Whether to encrypt the nonce with the election public key
    #[arg(long, default_value_t = false)]
    encrypt_nonce: bool,

    /// File from which to read the election manifest.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Use the example election manifest.
    #[arg(long)]
    example_manifest: bool,

    /// Number of ballots to generate
    #[arg(short, long, default_value_t = 1)]
    num_ballots: usize,

    /// Generate ballots
    #[arg(long, default_value_t = false)]
    generate: bool,

    /// Verify ballots
    #[arg(long, default_value_t = false)]
    verify: bool,

    // Tag for ballot verification
    #[arg(long, default_value_t = String::from(""))]
    tag: String,
}

impl Subcommand for PreEncryptedBallots {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        // let mut csprng = subcommand_helper.get_csprng(b"VerifyStandardParameters")?;

        // use eg::standard_parameters::STANDARD_PARAMETERS;
        // let fixed_parameters = &*STANDARD_PARAMETERS;

        // if self.example_manifest && self.manifest.is_some() {
        //     bail!("Specify either --example-manifest or --manifest, but not both.");
        // }

        // let election_parameters: ElectionParameters;
        // let election_manifest: ElectionManifest;

        // if self.example_manifest {
        //     election_parameters = example_election_parameters();
        //     election_manifest = example_election_manifest_small();
        // } else {
        //     return Err(anyhow::anyhow!("Not implemented yet"));
        // }

        // let path = Path::new(&subcommand_helper.artifacts_dir.dir_path).join("guardians");
        // let mut capital_k_i = Vec::with_capacity(election_parameters.varying_parameters.n as usize);
        // let mut proofs = Vec::with_capacity(election_parameters.varying_parameters.n as usize);

        // for i in 1..election_parameters.varying_parameters.n + 1 {
        //     // let their_artifacts = ArtifactsDir::new(&path.join(format!("{}", i))).unwrap();
        //     capital_k_i.push(PublicKey::new_from_file(
        //         &subcommand_helper
        //             .artifacts_dir
        //             .path(ArtifactFile::GuardianPublicKey(i)),
        //     ));
        //     proofs.push(ProofGuardian::from_json(
        //         &String::from_utf8(read_path(
        //             &subcommand_helper
        //                 .artifacts_dir
        //                 .path(ArtifactFile::GuardianProof(i)),
        //         ))
        //         .unwrap(),
        //     ));
        // }
        // let mut commitments = Vec::new();
        // proofs
        //     .iter()
        //     .for_each(|p| commitments.extend(p.capital_k.clone()));

        // let election_public_key = PublicKey(aggregate_public_keys(fixed_parameters, &capital_k_i));

        // let hashes = Hashes::new_with_extended(
        //     &election_parameters,
        //     &election_manifest,
        //     &election_public_key,
        //     &commitments,
        // );

        // let mut uuid = "".to_string();
        // if self.generate {
        //     uuid = "BallotEncryptingDevice".to_string();
        // } else if self.verify {
        //     uuid = "BallotRecordingDevice".to_string();
        // }

        // let record_header = ElectionRecordHeader::new(
        //     election_manifest,
        //     election_parameters,
        //     hashes,
        //     proofs,
        //     election_public_key,
        // );
        // let device = Device::new(&uuid, record_header.clone());

        // let path = Path::new(&subcommand_helper.artifacts_dir.dir_path).join("ballots");

        // if self.generate {
        //     // Write election record header to file
        //     subcommand_helper
        //         .artifacts_dir
        //         .out_file_write(
        //             &Some(
        //                 subcommand_helper
        //                     .artifacts_dir
        //                     .path(ArtifactFile::ElectionRecordHeader),
        //             ),
        //             ArtifactFile::ElectionRecordHeader,
        //             "Election Record Header",
        //             record_header.to_canonical_bytes().as_slice(),
        //         )
        //         .unwrap();
        //     // BallotListPreEncrypted::new(&device.header, &mut csprng, &path, self.num_ballots);
        //     let tool =
        //         BallotEncryptingTool::new(device.header, BallotStyle(vec!["".to_string()]), None);
        //     tool.generate_and_save_ballots(&mut csprng, self.num_ballots, &path);
        // } else if self.verify {
        //     let mut ballots: BallotListPreEncrypted;
        //     match BallotListPreEncrypted::read_from_directory(
        //         &subcommand_helper
        //             .artifacts_dir
        //             .dir_path
        //             .join(format!("ballots/{}", self.tag.as_str())),
        //     ) {
        //         Some(b) => ballots = b,
        //         None => bail!("Error reading ballots."),
        //     }

        //     for b_idx in 0..ballots.ballots.len() {
        //         Logging::log(
        //             "Pre-Encrypted",
        //             &format!("Verifying Ballot {}", b_idx + 1),
        //             line!(),
        //             file!(),
        //         );

        //         let pre_encrypted_ballot = &mut ballots.ballots[b_idx];
        //         assert!(BallotRecordingTool::verify_ballot(
        //             &device.header,
        //             &pre_encrypted_ballot,
        //             &ballots.primary_nonces[b_idx]
        //         ));

        //         BallotRecordingTool::regenerate_nonces(
        //             &device,
        //             pre_encrypted_ballot,
        //             &ballots.primary_nonces[b_idx],
        //         );

        //         let voter_ballot = BallotDecrypted::new_pick_random(
        //             &device.header.manifest,
        //             &mut csprng,
        //             String::from("Random Voter"),
        //         );

        //         let encrypted_ballot =
        //             pre_encrypted_ballot.finalize(&device, &mut csprng, &voter_ballot);

        //         encrypted_ballot.confirmation_code_qr(&path.join(self.tag.as_str()));

        //         encrypted_ballot.verification_code_qr(
        //             &voter_ballot,
        //             ballots.primary_nonces[b_idx].as_ref(),
        //             &path.join(self.tag.as_str()),
        //         );

        //         BallotRecordingTool::verify_ballot_proofs(&device, &encrypted_ballot);
        //     }
        // }

        Ok(())
    }
}
