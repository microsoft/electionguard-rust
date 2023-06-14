// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::{Path, PathBuf};

use crate::{Clargs, Subcommand};
use anyhow::{bail, Result};
use clap::Args;
use eg::{
    ballot::{
        EncryptedBallot, EncryptedBallotConfig, EncryptedContest, PreEncryptedBallotList,
        VoterBallot,
    },
    ballot_recording_tool::BallotRecordingTool,
    example_election_manifest::{example_election_manifest, example_election_manifest_small},
    example_election_parameters::example_election_parameters,
    guardian::aggregate_public_keys,
    hash::hex_to_bytes,
    hashes::Hashes,
    key::PublicKey,
};
use util::csprng::Csprng;

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
    // ballot_style: BallotStyle,
    // election_public_key: PublicKey,
    // encrypt_nonce: bool,
    /// Path to election data store
    #[arg(long, default_value_t = String::from("data"))]
    data: String,

    /// Verify generated ballots
    #[arg(long, default_value_t = false)]
    generate: bool,

    /// Number of ballots to generate
    #[arg(short, long, default_value_t = 1)]
    num_ballots: usize,

    /// Verify generated ballots
    #[arg(long, default_value_t = false)]
    verify: bool,

    /// Tag
    #[arg(long, default_value_t = String::from(""))]
    tag: String,
}

impl Subcommand for PreEncryptedBallots {
    fn need_csprng(&self) -> bool {
        true
    }

    fn do_it(&self, _clargs: &Clargs) -> Result<()> {
        bail!("need csprng version instead");
    }

    fn do_it_with_csprng(&self, _clargs: &Clargs, mut csprng: Csprng) -> Result<()> {
        use eg::standard_parameters::STANDARD_PARAMETERS;
        let fixed_parameters = &*STANDARD_PARAMETERS;

        if self.example_manifest && self.manifest.is_some() {
            bail!("Specify either --example-manifest or --manifest, but not both.");
        }

        if self.generate && self.verify {
            bail!("Specify either --generate or --verify, but not both.");
        }

        if self.example_manifest {
            println!("Using sample manifest.");

            let election_parameters = example_election_parameters();
            let election_manifest = example_election_manifest_small();
            let election_public_key: PublicKey;

            let path = Path::new(&self.data).join("guardians");

            let capital_k_i = (1..election_parameters.varying_parameters.n + 1)
                .map(|i| {
                    PublicKey::new_from_file(&path.join(format!("{}/public/public_key.json", i)))
                })
                .collect::<Vec<PublicKey>>();

            election_public_key = PublicKey(aggregate_public_keys(fixed_parameters, &capital_k_i));

            let hashes = Hashes::new(&election_parameters, &election_manifest);

            let config: EncryptedBallotConfig = EncryptedBallotConfig {
                manifest: election_manifest,
                election_public_key: election_public_key,
                h_e: hashes.h_p,
            };

            let path = Path::new(&self.data).join("ballots");

            if self.generate {
                PreEncryptedBallotList::new(
                    &config,
                    fixed_parameters,
                    &mut csprng,
                    &path,
                    self.num_ballots,
                );
            }

            if self.verify {
                let mut ballots: PreEncryptedBallotList;

                match PreEncryptedBallotList::read_from_directory(&path.join(self.tag.as_str())) {
                    Some(b) => ballots = b,
                    None => bail!("Error reading ballots."),
                }

                for b_idx in 0..ballots.ballots.len() {
                    let pre_encrypted_ballot = &mut ballots.ballots[b_idx];
                    assert!(BallotRecordingTool::verify_ballot(
                        &config,
                        fixed_parameters,
                        &pre_encrypted_ballot,
                        &ballots.primary_nonces[b_idx]
                    ));

                    BallotRecordingTool::regenerate_nonces(
                        pre_encrypted_ballot,
                        &config,
                        fixed_parameters,
                        hex_to_bytes(&ballots.primary_nonces[b_idx]).as_slice(),
                    );

                    let voter_ballot = VoterBallot::new_pick_random(
                        &config,
                        &mut csprng,
                        String::from("Random Voter"),
                    );

                    let encrypted_ballot = EncryptedBallot::new_from_preencrypted(
                        &config,
                        fixed_parameters,
                        &mut csprng,
                        pre_encrypted_ballot,
                        &voter_ballot,
                    );

                    encrypted_ballot.instant_verification_code(
                        &ballots.primary_nonces[b_idx],
                        &path.join(self.tag.as_str()),
                    );

                    println!("{:?}", config.h_e);

                    println!("Voter selections = {:?}", voter_ballot);

                    BallotRecordingTool::verify_ballot_proofs(
                        &config,
                        fixed_parameters,
                        &encrypted_ballot,
                    );
                }
            }
        } else if self.manifest.is_some() {
            todo!();
        }

        Ok(())
    }
}
