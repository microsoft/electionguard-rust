use eg::election_record::ElectionRecordHeader;
use eg::hash::HValue;
use util::logging::Logging;

use crate::ballot::BallotPreEncrypted;
use crate::contest::ContestPreEncrypted;
use crate::contest_selection::ContestSelectionPreEncrypted;
use crate::nonce::option_nonce;
use eg::ballot::BallotEncrypted;
use eg::contest::ContestEncrypted;
use eg::contest_selection::ContestSelectionCiphertext;
use eg::device::Device;
use eg::fixed_parameters::FixedParameters;
use eg::nizk::ProofRange;

pub struct BallotRecordingTool {}

impl BallotRecordingTool {
    pub fn verify_ballot(
        header: &ElectionRecordHeader,
        ballot: &BallotPreEncrypted,
        primary_nonce: &HValue,
    ) -> bool {
        let regenerated_ballot = BallotPreEncrypted::new_with(header, &primary_nonce.0);
        if ballot.get_confirmation_code() == regenerated_ballot.get_confirmation_code() {
            return BallotRecordingTool::verify_ballot_contests(
                &header.parameters.fixed_parameters,
                ballot.get_contests(),
                regenerated_ballot.get_contests(),
            );
        } else {
            Logging::log(
                "BallotRecordingTool",
                &format!(
                    "Ballot crypto hash mismatch {} {}.",
                    ballot.get_confirmation_code(),
                    regenerated_ballot.get_confirmation_code()
                ),
                line!(),
                file!(),
            );
            return false;
        }

        // match BallotPreEncrypted::new_with(header, &primary_nonce.0) {
        //     Some(regenerated_ballot) => {

        //     }
        //     None => {
        //         println!("Error regenerating ballot.");
        //         return false;
        //     }
        // }
    }

    pub fn regenerate_nonces(
        device: &Device,
        ballot: &mut BallotPreEncrypted,
        primary_nonce: &HValue,
    ) {
        let selection_labels = device
            .header
            .manifest
            .contests
            .iter()
            .map(|c| {
                c.options
                    .iter()
                    .map(|s| s.label.clone())
                    .collect::<Vec<String>>()
            })
            .collect::<Vec<Vec<String>>>();
        for i in 0..ballot.get_contests().len() {
            for j in 0..ballot.get_contests()[i].selections.len() {
                // Selection vectors corresponding to candidates
                if j < selection_labels[i].len() {
                    for k in 0..ballot.get_contests()[i].selections[j]
                        .get_selections()
                        .len()
                    {
                        ballot.contests[i].selections[j].selections[k] =
                            ContestSelectionCiphertext {
                                ciphertext: ballot.get_contests()[i].get_selections()[j]
                                    .get_selections()[k]
                                    .ciphertext
                                    .clone(),
                                nonce: option_nonce(
                                    &device.header,
                                    primary_nonce.as_ref(),
                                    ballot.get_contests()[i].label.as_bytes(),
                                    selection_labels[i][j].as_bytes(),
                                    selection_labels[i][k].as_bytes(),
                                ),
                            };
                    }
                }
                // Selection vectors corresponding to null votes
                else {
                    for k in 0..ballot.get_contests()[i].selections[j]
                        .get_selections()
                        .len()
                    {
                        ballot.contests[i].selections[j].selections[k] =
                            ContestSelectionCiphertext {
                                ciphertext: ballot.get_contests()[i].get_selections()[j]
                                    .get_selections()[k]
                                    .ciphertext
                                    .clone(),
                                nonce: option_nonce(
                                    &device.header,
                                    primary_nonce.as_ref(),
                                    ballot.get_contests()[i].label.as_bytes(),
                                    format!("null_{}", j + 1 - selection_labels[i].len())
                                        .as_bytes(),
                                    selection_labels[i][k].as_bytes(),
                                ),
                            };
                    }
                }
            }
        }
    }

    pub fn verify_ballot_proofs(device: &Device, ballot: &BallotEncrypted) {
        let tag = "Pre-Encrypted";
        for (i, contest) in ballot.contests.iter().enumerate() {
            // Verify proof of ballot correctness
            Logging::log(
                tag,
                &format!("  Verifying proofs for contest {}", i,),
                line!(),
                file!(),
            );

            for (j, proof) in contest.get_proof_ballot_correctness().iter().enumerate() {
                Logging::log(
                    tag,
                    &format!(
                        "    Ballot correctness / {}: {:?}",
                        j,
                        proof.verify(
                            &device.header,
                            &contest.selection.vote[j].ciphertext,
                            1 as usize,
                        )
                    ),
                    line!(),
                    file!(),
                );
            }

            // Verify proof of satisfying the selection limit
            Logging::log(
                tag,
                &format!(
                    "    Selection limit: {:?}",
                    contest.get_proof_selection_limit().verify(
                        &device.header,
                        &ContestEncrypted::sum_selection_vector(
                            &device.header.parameters.fixed_parameters,
                            &contest.selection.vote
                        )
                        .ciphertext,
                        device.header.manifest.contests[i].selection_limit,
                    )
                ),
                line!(),
                file!(),
            );
        }
    }

    fn verify_ballot_contests(
        fixed_parameters: &FixedParameters,
        contests: &Vec<ContestPreEncrypted>,
        regenerated_contests: &Vec<ContestPreEncrypted>,
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
        selections: &Vec<ContestSelectionPreEncrypted>,
        regenerated_selections: &Vec<ContestSelectionPreEncrypted>,
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
        device: &Device,
        selections: &Vec<Vec<ContestSelectionCiphertext>>,
        proofs: &Vec<Vec<ProofRange>>,
    ) -> bool {
        for (i, contest_selection) in selections.iter().enumerate() {
            for (j, vote) in contest_selection.iter().enumerate() {
                if !proofs[i][j].verify(
                    &device.header,
                    &vote.ciphertext,
                    device.header.manifest.contests[i].selection_limit,
                ) {
                    return false;
                };
            }
        }
        true
    }
}
