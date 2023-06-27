// Copyright (C) Microsoft Corporation. All rights reserved.

use eg::ballot::BallotStyle;
use eg::election_record::ElectionRecordHeader;
use eg::hash::{eg_h, HValue, HVALUE_BYTE_LEN};
use eg::joint_election_public_key::{Ciphertext, JointElectionPublicKey};
use util::csprng::Csprng;
use util::logging::Logging;

use crate::ballot::BallotPreEncrypted;

pub struct BallotEncryptingTool {
    pub header: ElectionRecordHeader,
    pub ballot_style: BallotStyle,
    pub encryption_key: Option<JointElectionPublicKey>,
}

pub struct EncryptedNonce {
    pub encrypted_nonce: Ciphertext,
}

impl BallotEncryptingTool {
    pub fn new(
        header: ElectionRecordHeader,
        ballot_style: BallotStyle,
        encryption_key: Option<JointElectionPublicKey>,
    ) -> Self {
        Self {
            header,
            ballot_style,
            encryption_key,
        }
    }

    pub fn print_ballot(i: usize, ballot: &BallotPreEncrypted, primary_nonce: &str) {
        let tag = "Pre-Encrypted";
        Logging::log(tag, &format!("Ballot {}", i), line!(), file!());
        Logging::log(tag, "  Primary Nonce", line!(), file!());
        Logging::log(tag, &format!("    {}", primary_nonce), line!(), file!());
        Logging::log(tag, "  Confirmation Code", line!(), file!());
        Logging::log(
            tag,
            &format!("    {}", ballot.confirmation_code),
            line!(),
            file!(),
        );
        Logging::log(tag, "  Contests", line!(), file!());
        ballot.contests.iter().for_each(|c| {
            Logging::log(tag, &format!("    {}", c.contest_hash), line!(), file!());
        });
    }

    pub fn generate_ballots(
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
}

/// Returns the last byte of the hash value
pub fn generate_short_code(full_hash: &HValue) -> String {
    String::from(full_hash.0[HVALUE_BYTE_LEN - 1] as char)
}

/// Checks whether previous selections contain the same short code
// pub fn check_shortcode(
//     previous: &Vec<ContestSelectionPreEncrypted>,
//     current: &ContestSelectionPreEncrypted,
// ) -> bool {
//     for other in previous.iter() {
//         if other.shortcode == current.shortcode {
//             return false;
//         }
//     }
//     true
// }

/// Generates a selection hash (Equation 93/94)
///
/// ψ_i = H(H_E;40,[λ_i],K,α_1,β_1,α_2,β_2 ...,α_m,β_m),
///
/// TODO: Remove label from the hash (equation 93)
pub fn selection_hash(header: &ElectionRecordHeader, selections: &Vec<Ciphertext>) -> HValue {
    let mut v = vec![0x40];

    v.extend_from_slice(header.public_key.0.to_bytes_be().as_slice());

    selections.iter().for_each(|s| {
        v.extend_from_slice(s.alpha.to_bytes_be().as_slice());
        v.extend_from_slice(s.beta.to_bytes_be().as_slice());
    });

    eg_h(&header.hashes_ext.h_e, &v)
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
