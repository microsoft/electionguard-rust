use num_bigint::BigUint;
use num_traits::Num;
use util::csprng::Csprng;

use crate::ballot::{
    CiphertextContestSelection, PreEncryptedBallot, PreEncryptedBallotConfig, PreEncryptedContest,
    PreEncryptedContestSelection,
};
use crate::ballot_encrypting_tool::BallotEncryptingTool;
use crate::fixed_parameters::FixedParameters;
use crate::nizk::ProofRange;

pub struct BallotRecordingTool {}

impl BallotRecordingTool {
    pub fn verify_ballot(
        config: &PreEncryptedBallotConfig,
        fixed_parameters: &FixedParameters,
        ballot: &PreEncryptedBallot,
        primary_nonce_str: &str,
    ) -> bool {
        let mut primary_nonce = Vec::new();
        println!("primary_nonce_str: {}", primary_nonce_str);
        match BigUint::from_str_radix(primary_nonce_str, 16) {
            Ok(nonce) => primary_nonce.extend_from_slice(nonce.to_bytes_be().as_slice()),
            Err(e) => {
                println!("Error parsing primary nonce: {}", e);
                return false;
            }
        };

        match PreEncryptedBallot::try_new_with(config, fixed_parameters, primary_nonce.as_slice()) {
            Some(regenerated_ballot) => {
                if *ballot.get_crypto_hash() == *regenerated_ballot.get_crypto_hash() {
                    return BallotRecordingTool::verify_ballot_contests(
                        fixed_parameters,
                        ballot.get_contests(),
                        regenerated_ballot.get_contests(),
                    );
                } else {
                    println!(
                        "Ballot crypto hash mismatch {} {}.",
                        ballot.get_crypto_hash(),
                        regenerated_ballot.get_crypto_hash()
                    );
                    return false;
                }
            }
            None => {
                println!("Error regenerating ballot.");
                return false;
            }
        }
        false
    }

    pub fn regenerate_nonces(
        ballot: &mut PreEncryptedBallot,
        config: &PreEncryptedBallotConfig,
        fixed_parameters: &FixedParameters,
        primary_nonce: &[u8],
    ) {
        let selection_labels = config
            .manifest
            .contests
            .iter()
            .map(|c| {
                PreEncryptedContest::sanitize_contest(c)
                    .options
                    .iter()
                    .map(|s| s.label.clone())
                    .collect::<Vec<String>>()
            })
            .collect::<Vec<Vec<String>>>();
        for i in 0..ballot.get_contests().len() {
            for j in 0..ballot.get_contests()[i].selections.len() {
                for k in 0..ballot.get_contests()[i].selections[j]
                    .get_selections()
                    .len()
                {
                    ballot.contests[i].selections[j].selections[k] = CiphertextContestSelection {
                        ciphertext: ballot.get_contests()[i].get_selections()[j].get_selections()
                            [k]
                            .ciphertext
                            .clone(),
                        nonce: BallotEncryptingTool::generate_nonce(
                            config,
                            primary_nonce,
                            ballot.get_contests()[i].label.as_bytes(),
                            selection_labels[i][j].as_bytes(),
                            selection_labels[i][k].as_bytes(),
                            fixed_parameters,
                        ),
                    };
                }

                // contest.selections[j].regenerate_nonces(
                //     config,
                //     fixed_parameters,
                //     primary_nonce,
                //     &contest.label,
                //     &selection_labels[i],
                //     j,
                // );
            }
        }
    }

    pub fn verify_ballot_proofs(
        config: &PreEncryptedBallotConfig,
        fixed_parameters: &FixedParameters,
        csprng: &mut Csprng,
        ballot: &PreEncryptedBallot,
        voter_selections: &Vec<Vec<usize>>,
    ) {
        let (proof_ballot_correctness, proof_selection_limit) =
            ballot.nizkp(csprng, fixed_parameters, &config, &voter_selections);

        // Verify proof of ballot correctness
        for (i, ballot_proof) in proof_ballot_correctness.iter().enumerate() {
            for (j, contest_proof) in ballot_proof.iter().enumerate() {
                for (k, selection_proof) in contest_proof.iter().enumerate() {
                    println!(
                        "Verify proof of ballot correctness i: {}, j: {}, k: {}",
                        i, j, k
                    );
                    // TODO: Nonces are all zero
                    assert!(selection_proof.verify(
                        fixed_parameters,
                        &config,
                        &ballot.get_contests()[i].get_selections()[j].get_selections()[k]
                            .ciphertext,
                        1 as usize,
                    ));
                }
            }

            let combined_selection = PreEncryptedContest::sum_selection_vector(
                fixed_parameters,
                &ballot.get_contests()[i]
                    .combine_voter_selections(fixed_parameters, voter_selections[i].as_slice()),
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

    fn verify_ballot_contests(
        fixed_parameters: &FixedParameters,
        contests: &Vec<PreEncryptedContest>,
        regenerated_contests: &Vec<PreEncryptedContest>,
    ) -> bool {
        assert!(contests.len() == regenerated_contests.len());
        for (i, a) in contests.iter().enumerate() {
            if a.crypto_hash != regenerated_contests[i].crypto_hash {
                println!("Contest crypto hash mismatch.");
                return false;
            }
            BallotRecordingTool::verify_contest_selections(
                fixed_parameters,
                &a.selections,
                &regenerated_contests[i].selections,
            );
        }
        true
    }

    fn verify_contest_selections(
        fixed_parameters: &FixedParameters,
        selections: &Vec<PreEncryptedContestSelection>,
        regenerated_selections: &Vec<PreEncryptedContestSelection>,
    ) -> bool {
        assert!(selections.len() == regenerated_selections.len());

        // eprintln!("Number of voter selections:\t{}", voter_selections.len());

        for (i, a) in selections.iter().enumerate() {
            if a.crypto_hash != regenerated_selections[i].crypto_hash {
                return false;
            }
            assert!(a.selections.len() == regenerated_selections[i].selections.len());
            for (j, s) in a.selections.iter().enumerate() {
                if s.ciphertext != regenerated_selections[i].selections[j].ciphertext {
                    return false;
                }
            }
        }

        // if ctxts_to_combine.len() == 0 {
        //     return false;
        // }

        // // combined_selection
        true
    }

    // pub fn proof_of_ballot_correctness(
    //     csprng: &mut Csprng,
    //     config: &PreEncryptedBallotConfig,
    //     fixed_parameters: &FixedParameters,
    //     ballot: &PreEncryptedBallot,
    //     voter_selections: &Vec<Vec<usize>>,
    // ) -> (Vec<Vec<ProofRange>>, Vec<Vec<CiphertextContestSelection>>) {
    //     let mut proofs = vec![<Vec<ProofRange>>::new(); ballot.get_contests().len()];
    //     let mut combined_selections =
    //         vec![<Vec<CiphertextContestSelection>>::new(); ballot.get_contests().len()];

    //     for (i, contest) in ballot.get_contests().iter().enumerate() {
    //         assert!(voter_selections.len() <= config.manifest.contests[i].selection_limit);
    //         if voter_selections[i].len() == 0 {
    //             todo!();
    //         } else if voter_selections[i].len() == 1 {
    //             combined_selections[i] = contest.selections[voter_selections[i][0]]
    //                 .selections
    //                 .clone();
    //         } else {
    //             let mut selections_to_combine = voter_selections[i]
    //                 .iter()
    //                 .map(|j| &contest.selections[*j].selections)
    //                 .collect::<Vec<&Vec<CiphertextContestSelection>>>();
    //             combined_selections[i] =
    //                 homomorphic_addition(selections_to_combine, fixed_parameters)
    //         }

    //         let mut votes = vec![false; contest.selections.len()];
    //         for v in &voter_selections[i] {
    //             votes[*v] = true;
    //         }
    //         proofs[i] = (0..combined_selections[i].len())
    //             .map(|j| {
    //                 ProofRange::new(
    //                     csprng,
    //                     fixed_parameters,
    //                     config.h_e,
    //                     &config.election_public_key,
    //                     &combined_selections[i][j].nonce,
    //                     &combined_selections[i][j].ciphertext,
    //                     config.manifest.contests[i].selection_limit,
    //                     votes[j] as usize,
    //                 )
    //             })
    //             .collect::<Vec<_>>();
    //     }
    //     (proofs, combined_selections)
    // }

    pub fn verify_proof_of_ballot_correctness(
        config: &PreEncryptedBallotConfig,
        fixed_parameters: &FixedParameters,
        selections: &Vec<Vec<CiphertextContestSelection>>,
        proofs: &Vec<Vec<ProofRange>>,
    ) -> bool {
        for (i, contest_selection) in selections.iter().enumerate() {
            for (j, vote) in contest_selection.iter().enumerate() {
                if !proofs[i][j].verify(
                    fixed_parameters,
                    config,
                    &vote.ciphertext,
                    config.manifest.contests[i].selection_limit,
                ) {
                    return false;
                };
            }
        }
        true
    }
}
