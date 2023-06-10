// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{
    borrow::Borrow,
    fmt::format,
    fs,
    path::{Path, PathBuf},
};

use crate::{guardian, Clargs, Subcommand};
use anyhow::{bail, Result};
use clap::Args;
use eg::{
    ballot::{PreEncryptedBallot, PreEncryptedBallotConfig, PreEncryptedContest},
    ballot_encrypting_tool::BallotEncryptingTool,
    ballot_recording_tool::BallotRecordingTool,
    election_parameters::ElectionParameters,
    example_election_manifest::{example_election_manifest, example_election_manifest_small},
    example_election_parameters::example_election_parameters,
    guardian::aggregate_public_keys,
    hashes::Hashes,
    key::{self, PublicKey},
    varying_parameters::VaryingParameters,
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
    #[arg(long, default_value_t = String::from("election-data"))]
    data: String,

    /// Number of ballots to generate
    #[arg(short, long, default_value_t = 1)]
    num_ballots: usize,

    /// Verify generated ballots
    #[arg(long, default_value_t = false)]
    verify: bool,
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

        if self.example_manifest {
            println!("Using sample manifest.");

            let election_parameters = example_election_parameters();
            let election_manifest = example_election_manifest();
            let election_public_key: PublicKey;

            let path = Path::new(&self.data).join("guardians");

            let capital_k_i = (1..election_parameters.varying_parameters.n + 1)
                .map(|i| {
                    PublicKey::new_from_file(&path.join(format!("{}/public/public_key.json", i)))
                })
                .collect::<Vec<PublicKey>>();

            election_public_key = PublicKey(aggregate_public_keys(fixed_parameters, &capital_k_i));

            let hashes = Hashes::new(&election_parameters, &election_manifest);

            let voter_selections = election_manifest
                .contests
                .iter()
                .map(|contest| {
                    let mut vote = <Vec<usize>>::new();
                    let num_selections = 1 as u64;
                    (0..num_selections).for_each(|_| {
                        vote.push(csprng.next_u64() as usize % (contest.options.len() + 1));
                    });
                    vote
                })
                .collect::<Vec<Vec<usize>>>();

            let config: PreEncryptedBallotConfig = PreEncryptedBallotConfig {
                manifest: election_manifest,
                election_public_key: election_public_key,
                encrypt_nonce: self.encrypt_nonce,
                h_e: hashes.h_p,
            };

            let path = Path::new(&self.data).join("ballots");
            fs::create_dir_all(path.join("public")).unwrap();
            fs::create_dir_all(path.join("private")).unwrap();

            for b_idx in 0..self.num_ballots {
                let mut primary_nonce = [0u8; 32];
                (0..32).for_each(|i| primary_nonce[i] = csprng.next_u8());

                let (ballot, primary_nonce) =
                    PreEncryptedBallot::new(&config, fixed_parameters, &mut csprng);

                if self.verify {
                    assert!(BallotRecordingTool::verify_ballot(
                        &config,
                        fixed_parameters,
                        &ballot,
                        primary_nonce.as_slice()
                    ));

                    let (proof_ballot_correctness, proof_selection_limit) =
                        ballot.nizkp(&mut csprng, fixed_parameters, &config, &voter_selections);

                    // Verify proof of ballot correctness
                    for (i, ballot_proof) in proof_ballot_correctness.iter().enumerate() {
                        for (j, contest_proof) in ballot_proof.iter().enumerate() {
                            for (k, selection_proof) in contest_proof.iter().enumerate() {
                                println!(
                                    "Verify proof of ballot correctness i: {}, j: {}, k: {}",
                                    i, j, k
                                );
                                assert!(selection_proof.verify(
                                    fixed_parameters,
                                    &config,
                                    &ballot.get_contests()[i].get_selections()[j].get_selections()
                                        [k]
                                        .ciphertext,
                                    1 as usize,
                                ));
                            }
                        }

                        let combined_selection = PreEncryptedContest::sum_selection_vector(
                            fixed_parameters,
                            &ballot.get_contests()[i].combine_voter_selections(
                                fixed_parameters,
                                voter_selections[i].as_slice(),
                            ),
                        );

                        println!("Verify proof of satisfying the selection limit {}", i);
                        // Verify proof of satisfying the selection limit
                        assert!(proof_selection_limit[i].verify(
                            fixed_parameters,
                            &config,
                            &combined_selection.ciphertext,
                            config.manifest.contests[i].selection_limit,
                        ));
                    }
                }

                let confirmation_code = ballot.get_crypto_hash().to_string();
                ballot.write_to_file(&path.join(format!("public/{}.json", confirmation_code)));

                PreEncryptedBallot::write_primary_nonce_to_file(
                    &path.join(format!("private/{}.txt", confirmation_code)),
                    &primary_nonce,
                )
            }
        } else if self.manifest.is_some() {
            todo!();
        }

        Ok(())
    }
}
