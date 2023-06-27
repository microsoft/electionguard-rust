use crate::{
    ballot::BallotPreEncrypted, contest::ContestPreEncrypted,
    contest_selection::ContestSelectionPreEncrypted, nonce::option_nonce,
};
use eg::{
    ballot::BallotEncrypted, contest::ContestEncrypted, device::Device,
    election_record::ElectionRecordHeader, hash::HValue, joint_election_public_key::Ciphertext,
    zk::ProofRange,
};
use util::logging::Logging;

pub struct BallotRecordingTool {}

impl BallotRecordingTool {
    pub fn verify_ballot(
        header: &ElectionRecordHeader,
        ballot: &BallotPreEncrypted,
        primary_nonce: &HValue,
    ) -> bool {
        let regenerated_ballot = BallotPreEncrypted::new_with(header, &primary_nonce.0);
        if ballot.confirmation_code == regenerated_ballot.confirmation_code {
            return BallotRecordingTool::verify_ballot_contests(
                &ballot.contests,
                &regenerated_ballot.contests,
            );
        } else {
            Logging::log(
                "BallotRecordingTool",
                &format!(
                    "Ballot crypto hash mismatch {} {}.",
                    ballot.confirmation_code, regenerated_ballot.confirmation_code
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

        for i in 0..ballot.contests.len() {
            for j in 0..ballot.contests[i].selections.len() {
                // Selection vectors corresponding to candidates
                if j < selection_labels[i].len() {
                    for k in 0..ballot.contests[i].selections[j].selections.len() {
                        ballot.contests[i].selections[j].selections[k].nonce = Some(option_nonce(
                            &device.header,
                            primary_nonce.as_ref(),
                            ballot.contests[i].label.as_bytes(),
                            selection_labels[i][j].as_bytes(),
                            selection_labels[i][k].as_bytes(),
                        ));
                    }
                }
                // Selection vectors corresponding to null votes
                else {
                    for k in 0..ballot.contests[i].selections[j].selections.len() {
                        ballot.contests[i].selections[j].selections[k].nonce = Some(option_nonce(
                            &device.header,
                            primary_nonce.as_ref(),
                            ballot.contests[i].label.as_bytes(),
                            format!("null_{}", j + 1 - selection_labels[i].len()).as_bytes(),
                            selection_labels[i][k].as_bytes(),
                        ));
                    }
                }
            }
        }
    }

    pub fn verify_ballot_proofs(device: &Device, ballot: &BallotEncrypted) {
        let tag = "Pre-Encrypted";
        for (i, contest) in ballot.contests().iter().enumerate() {
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
                        proof.verify(&device.header, &contest.selection[j], 1 as usize,)
                    ),
                    line!(),
                    file!(),
                );
            }

            let ct_combined = ContestEncrypted::sum_selection_vector(
                &device.header.parameters.fixed_parameters,
                &contest.selection,
            );
            // Verify proof of satisfying the selection limit
            Logging::log(
                tag,
                &format!(
                    "    Selection limit: {:?}",
                    contest.get_proof_selection_limit().verify(
                        &device.header,
                        &ct_combined,
                        device.header.manifest.contests[i].selection_limit,
                    )
                ),
                line!(),
                file!(),
            );
        }
    }

    fn verify_ballot_contests(
        contests: &Vec<ContestPreEncrypted>,
        regenerated_contests: &Vec<ContestPreEncrypted>,
    ) -> bool {
        assert!(contests.len() == regenerated_contests.len());
        for (i, a) in contests.iter().enumerate() {
            if a.contest_hash != regenerated_contests[i].contest_hash {
                println!("Contest crypto hash mismatch.");
                return false;
            }
            BallotRecordingTool::verify_contest_selections(
                &a.selections,
                &regenerated_contests[i].selections,
            );
        }
        true
    }

    fn verify_contest_selections(
        selections: &Vec<ContestSelectionPreEncrypted>,
        regenerated_selections: &Vec<ContestSelectionPreEncrypted>,
    ) -> bool {
        assert!(selections.len() == regenerated_selections.len());

        for (i, a) in selections.iter().enumerate() {
            if a.selection_hash != regenerated_selections[i].selection_hash {
                return false;
            }
            assert!(a.selections.len() == regenerated_selections[i].selections.len());
            for (j, s) in a.selections.iter().enumerate() {
                if s.alpha != regenerated_selections[i].selections[j].alpha
                    || s.beta != regenerated_selections[i].selections[j].beta
                {
                    return false;
                }
            }
        }

        true
    }

    pub fn verify_proof_of_ballot_correctness(
        device: &Device,
        selections: &Vec<Vec<Ciphertext>>,
        proofs: &Vec<Vec<ProofRange>>,
    ) -> bool {
        for (i, contest_selection) in selections.iter().enumerate() {
            for (j, vote) in contest_selection.iter().enumerate() {
                if !proofs[i][j].verify(
                    &device.header,
                    &vote,
                    device.header.manifest.contests[i].selection_limit,
                ) {
                    return false;
                };
            }
        }
        true
    }
}
