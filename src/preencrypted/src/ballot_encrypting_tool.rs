// Copyright (C) Microsoft Corporation. All rights reserved.

use eg::ballot::BallotConfig;

use eg::contest_selection::ContestSelectionCiphertext;
use eg::hash::{eg_h, HValue, HVALUE_BYTE_LEN};

use crate::contest_selection::ContestSelectionPreEncrypted;

/// Returns the last byte of the hash value
pub fn generate_short_code(full_hash: &HValue) -> String {
    String::from(full_hash.0[HVALUE_BYTE_LEN - 1] as char)
}

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
    config: &BallotConfig,
    selections: &Vec<ContestSelectionCiphertext>,
) -> HValue {
    let mut v = vec![0x40];

    v.extend_from_slice(config.election_public_key.0.to_bytes_be().as_slice());

    selections.iter().for_each(|s| {
        v.extend_from_slice(s.ciphertext.alpha.to_bytes_be().as_slice());
        v.extend_from_slice(s.ciphertext.beta.to_bytes_be().as_slice());
    });

    eg_h(&config.h_e, &v)
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