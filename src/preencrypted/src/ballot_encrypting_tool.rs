// Copyright (C) Microsoft Corporation. All rights reserved.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use eg::ballot::BallotStyle;
use eg::contest_selection::ContestSelectionCiphertext;
use eg::election_manifest::ElectionManifest;
use eg::election_record::ElectionRecordHeader;
use eg::hash::{eg_h, HValue, HVALUE_BYTE_LEN};
use eg::key::{Ciphertext, PublicKey};
use util::csprng::Csprng;
use util::file::{create_path, write_path};
use util::logging::Logging;

use crate::ballot::BallotPreEncrypted;
use crate::contest_selection::ContestSelectionPreEncrypted;

pub struct BallotEncryptingTool {
    pub header: ElectionRecordHeader,
    pub ballot_style: BallotStyle,
    pub encryption_key: Option<PublicKey>,
}

pub struct EncryptedNonce {
    pub encrypted_nonce: Ciphertext,
}

impl BallotEncryptingTool {
    pub fn new(
        header: ElectionRecordHeader,
        ballot_style: BallotStyle,
        encryption_key: Option<PublicKey>,
    ) -> Self {
        Self {
            header,
            ballot_style,
            encryption_key,
        }
    }

    fn print_ballot(i: usize, ballot: &BallotPreEncrypted, primary_nonce: &str) {
        let tag = "Pre-Encrypted";
        Logging::log(tag, &format!("Ballot {}", i), line!(), file!());
        Logging::log(tag, "  Primary Nonce", line!(), file!());
        Logging::log(tag, &format!("    {}", primary_nonce), line!(), file!());
        Logging::log(tag, "  Confirmation Code", line!(), file!());
        Logging::log(
            tag,
            &format!("    {}", ballot.get_confirmation_code()),
            line!(),
            file!(),
        );
        Logging::log(tag, "  Contests", line!(), file!());
        ballot.get_contests().iter().for_each(|c| {
            Logging::log(
                tag,
                &format!("    {}", c.crypto_hash.to_string()),
                line!(),
                file!(),
            );
        });
    }

    fn generate_ballots(
        &self,
        csprng: &mut Csprng,
        num_ballots: usize,
    ) -> (Vec<BallotPreEncrypted>, Vec<HValue>) {
        let mut ballots = Vec::new();
        let mut primary_nonces = Vec::new();

        for _ in 0..num_ballots {
            let (ballot, nonce) = BallotPreEncrypted::new(&self.header, csprng);
            ballots.push(ballot);
            primary_nonces.push(nonce);
        }

        (ballots, primary_nonces)
    }

    /// Generates and writes to disk num_ballots pre-encrypted ballots
    pub fn generate_and_save_ballots(&self, csprng: &mut Csprng, num_ballots: usize, path: &Path) {
        let (ballots, primary_nonces) = self.generate_ballots(csprng, num_ballots);

        let label: String;
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(n) => {
                label = format!("{}", n.as_secs());
            }
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        }

        let path = path.join(label.clone());
        create_path(&path);
        let mut confirmation_codes = Vec::with_capacity(num_ballots);

        for b_idx in 0..num_ballots {
            Self::print_ballot(
                b_idx + 1,
                &ballots[b_idx],
                &primary_nonces[b_idx].to_string(),
            );
            confirmation_codes.push(ballots[b_idx].confirmation_code);
            write_path(
                &path.join(format!("ballot-{}.json", confirmation_codes[b_idx])),
                serde_json::to_string(&ballots[b_idx]).unwrap().as_bytes(),
            );
        }

        match &self.encryption_key {
            Some(key) => {}
            None => {
                write_path(
                    &path.join("primary-nonces.json"),
                    serde_json::to_string(&vec![confirmation_codes, primary_nonces.clone()])
                        .unwrap()
                        .as_bytes(),
                );
            }
        }
    }
}

/// Returns the last byte of the hash value
pub fn generate_short_code(full_hash: &HValue) -> String {
    String::from(full_hash.0[HVALUE_BYTE_LEN - 1] as char)
}

/// Checks whether previous selections contain the same short code
pub fn check_shortcode(
    previous: &Vec<ContestSelectionPreEncrypted>,
    current: &ContestSelectionPreEncrypted,
) -> bool {
    for other in previous.iter() {
        if other.shortcode == current.shortcode {
            return false;
        }
    }
    true
}

/// Generates a selection hash (Equation 93/94)
///
/// ψ_i = H(H_E;40,[λ_i],K,α_1,β_1,α_2,β_2 ...,α_m,β_m),
///
/// TODO: Remove label from the hash (equation 93)
pub fn generate_selection_hash(
    header: &ElectionRecordHeader,
    selections: &Vec<ContestSelectionCiphertext>,
) -> HValue {
    let mut v = vec![0x40];

    v.extend_from_slice(header.public_key.0.to_bytes_be().as_slice());

    selections.iter().for_each(|s| {
        v.extend_from_slice(s.ciphertext.alpha.to_bytes_be().as_slice());
        v.extend_from_slice(s.ciphertext.beta.to_bytes_be().as_slice());
    });

    eg_h(&header.hashes.h_e, &v)
}

// // Unit tests for pre-encrypted ballots.
// #[cfg(test)]
// mod test {

//     use super::*;
//     use crate::{
//         example_election_manifest::example_election_manifest_small,
//         example_election_parameters::example_election_parameters, hashes::Hashes, key::PrivateKey,
//         standard_parameters::STANDARD_PARAMETERS,
//     };
//     use hex_literal::hex;

//     #[test]
//     fn test_pre_encrypted_ballot_generation() {
//         let election_parameters = example_election_parameters();
//         let election_manifest = example_election_manifest_small();
//         let fixed_parameters = &*STANDARD_PARAMETERS;

//         let mut csprng = util::csprng::Csprng::new(1234);

//         let sk = PrivateKey::new(&mut csprng, fixed_parameters);

//         let hashes = Hashes::new(&election_parameters, &election_manifest);
//         // eprintln!("{:#?}", manifest.contests);

//         let config = PreEncryptedBallotConfig {
//             manifest: election_manifest,
//             election_public_key: sk.public_key().clone(),
//             encrypt_nonce: false,
//             h_e: hashes.h_p,
//         };

//         let mut primary_nonce = [0u8; 32];
//         (0..32).for_each(|i| primary_nonce[i] = csprng.next_u8());

//         let ballot = BallotEncryptingTool::generate_ballot_with(
//             &config,
//             fixed_parameters,
//             primary_nonce.as_slice(),
//         );
//         assert!(BallotRecordingTool::verify(
//             &config,
//             fixed_parameters,
//             &ballot,
//             primary_nonce.as_slice(),
//         ));
//     }
// }
