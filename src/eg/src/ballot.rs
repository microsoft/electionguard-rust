use std::path::Path;

use serde::{Deserialize, Serialize};
use util::csprng::Csprng;

use crate::{
    confirmation_code::encrypted,
    contest::ContestEncrypted,
    contest_selection::{ContestSelection, ContestSelectionEncrypted},
    device::Device,
    election_manifest::ElectionManifest,
    hash::HValue,
    voter::{VoterChallengeCode, VoterConfirmationCode},
};

/// An encrypted ballot.
#[derive(Debug)]
pub struct BallotEncrypted {
    /// Label
    pub label: String,

    /// Contests in this ballot
    pub contests: Vec<ContestEncrypted>,

    /// Confirmation code
    pub confirmation_code: HValue,

    /// Date (and time) of ballot generation
    pub date: String,

    /// Device that generated this ballot
    pub device: String,
}

/// A decrypted ballot.
#[derive(Debug)]
pub struct BallotDecrypted {
    /// Label
    pub label: String,

    /// Encrypted selections made by the voter
    pub encrypted_selections: Vec<ContestSelectionEncrypted>,

    /// Decrypted selections made by the voter
    pub decrypted_selections: Vec<ContestSelection>,

    /// Confirmation code
    pub confirmation_code: HValue,
}

// /// Configuration for generating encrypted ballots.
// #[derive(Clone)]
// pub struct BallotConfig {
//     /// Election manifest
//     pub manifest: ElectionManifest,
//     // ballot_style: BallotStyle,
//     /// Election public key
//     pub election_public_key: PublicKey,

//     /// Whether to encrypt the nonce with the election public key
//     // pub encrypt_nonce: bool,

//     /// Election extended base hash
//     pub h_e: HValue,
// }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// A ballot style is an ordered list of contest labels.
pub struct BallotStyle(pub Vec<String>);

impl BallotDecrypted {
    pub fn new_pick_random(
        manifest: &ElectionManifest,
        csprng: &mut Csprng,
        label: String,
    ) -> Self {
        let mut contests = Vec::new();
        for contest in &manifest.contests {
            contests.push(ContestSelection::new_pick_random(
                csprng,
                contest.selection_limit,
                contest.options.len(),
            ));
        }
        Self {
            label,
            decrypted_selections: contests,
            encrypted_selections: Vec::new(),
            confirmation_code: HValue::default(),
        }
    }
}

impl BallotEncrypted {
    pub fn new(
        device: &Device,
        csprng: &mut Csprng,
        primary_nonce: &[u8],
        selections: &Vec<ContestSelection>,
    ) -> BallotEncrypted {
        let mut contests = Vec::with_capacity(selections.len());

        for (i, selection) in selections.iter().enumerate() {
            contests.push(ContestEncrypted::new(
                device,
                csprng,
                primary_nonce,
                &device.header.manifest.contests[i],
                selection,
            ));
        }

        let confirmation_code = encrypted(&device.header.hashes.h_e, &contests, &vec![0u8; 32]);
        BallotEncrypted {
            label: String::new(),
            contests,
            confirmation_code,
            date: device.header.parameters.varying_parameters.date.clone(),
            device: device.uuid.clone(),
        }
    }

    pub fn confirmation_code_qr(&self, dir_path: &Path) {
        VoterConfirmationCode::new_as_file(dir_path, self.confirmation_code.as_ref());
    }

    pub fn verification_code_qr(
        &self,
        voter_ballot: &BallotDecrypted,
        primary_nonce: &[u8],
        dir_path: &Path,
    ) {
        VoterChallengeCode::new_as_file(
            dir_path,
            primary_nonce,
            self.confirmation_code.as_ref(),
            &voter_ballot.decrypted_selections,
        );
    }
}
