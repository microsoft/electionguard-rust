use crate::ballot::{
    CiphertextContestSelection, PreEncryptedBallot, PreEncryptedBallotConfig, PreEncryptedContest,
    PreEncryptedContestSelection,
};
use crate::fixed_parameters::FixedParameters;
use crate::nizk::ProofRange;

pub struct BallotRecordingTool {}

impl BallotRecordingTool {
    pub fn verify_ballot(
        config: &PreEncryptedBallotConfig,
        fixed_parameters: &FixedParameters,
        ballot: &PreEncryptedBallot,
        primary_nonce: &[u8],
    ) -> bool {
        match PreEncryptedBallot::try_new_with(config, fixed_parameters, primary_nonce) {
            Some(regenerated_ballot) => {
                if *ballot.get_crypto_hash() == *regenerated_ballot.get_crypto_hash() {
                    return BallotRecordingTool::verify_ballot_contests(
                        fixed_parameters,
                        ballot.get_contests(),
                        regenerated_ballot.get_contests(),
                    );
                }
            }
            None => return false,
        }
        false
    }

    fn verify_ballot_contests(
        fixed_parameters: &FixedParameters,
        contests: &Vec<PreEncryptedContest>,
        regenerated_contests: &Vec<PreEncryptedContest>,
    ) -> bool {
        assert!(contests.len() == regenerated_contests.len());
        for (i, a) in contests.iter().enumerate() {
            if a.crypto_hash != regenerated_contests[i].crypto_hash {
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
