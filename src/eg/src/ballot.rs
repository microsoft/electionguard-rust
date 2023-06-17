use std::path::Path;

use util::csprng::Csprng;

use crate::{
    contest::ContestEncrypted,
    contest_selection::{ContestSelection, ContestSelectionEncrypted},
    device::Device,
    election_manifest::ElectionManifest,
    hash::{hex_to_bytes, HValue},
    key::PublicKey,
    voter::VoterVerificationCode,
};

/// An encrypted ballot.
#[derive(Debug)]
pub struct BallotEncrypted {
    /// Label
    pub label: String,

    /// Contests in this ballot
    pub contests: Vec<ContestEncrypted>,

    /// Confirmation code
    pub confirmation_code: String,

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
    pub confirmation_code: String,
}

/// Configuration for generating encrypted ballots.
#[derive(Clone)]
pub struct BallotConfig {
    /// Election manifest
    pub manifest: ElectionManifest,
    // ballot_style: BallotStyle,
    /// Election public key
    pub election_public_key: PublicKey,

    /// Whether to encrypt the nonce with the election public key
    // pub encrypt_nonce: bool,

    /// Election extended base hash
    pub h_e: HValue,
}

impl BallotDecrypted {
    pub fn new_pick_random(config: &BallotConfig, csprng: &mut Csprng, label: String) -> Self {
        let mut contests = Vec::new();
        for contest in &config.manifest.contests {
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
            confirmation_code: "".to_string(),
        }
    }
}

impl BallotEncrypted {
    pub fn instant_verification_code(
        &self,
        device: &Device,
        voter_ballot: &BallotDecrypted,
        primary_nonce: &[u8],
        dir_path: &Path,
    ) {
        VoterVerificationCode::new_as_file(
            &device.config,
            dir_path,
            primary_nonce,
            &hex_to_bytes(&self.confirmation_code),
            &voter_ballot.decrypted_selections,
        );
    }
}
