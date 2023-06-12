// Copyright (C) Microsoft Corporation. All rights reserved.

use num_bigint::BigUint;

use crate::ballot::{
    CiphertextContestSelection, EncryptedBallotConfig, PreEncryptedContest,
    PreEncryptedContestSelection,
};

use crate::fixed_parameters::FixedParameters;
use crate::hash::{eg_h, hex_to_bytes};

pub struct BallotEncryptingTool {}

impl BallotEncryptingTool {
    /// Returns the last byte of the hash value
    pub fn generate_short_code(full_hash: &String) -> String {
        full_hash.chars().skip(full_hash.len() - 2).collect()
    }

    pub fn check_shortcode(
        previous: &Vec<PreEncryptedContestSelection>,
        current: &PreEncryptedContestSelection,
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
    /// ψ_i = H(H_E;40,λ_i,K,α_1,β_1,α_2,β_2 ...,α_m,β_m),
    ///
    /// TODO: Remove label from the hash (equation 93)
    pub fn generate_selection_hash(
        config: &EncryptedBallotConfig,
        selections: &Vec<CiphertextContestSelection>,
    ) -> String {
        let mut v = vec![0x40];

        v.extend_from_slice(config.election_public_key.0.to_bytes_be().as_slice());

        selections.iter().for_each(|s| {
            v.extend_from_slice(s.ciphertext.alpha.to_bytes_be().as_slice());
            v.extend_from_slice(s.ciphertext.beta.to_bytes_be().as_slice());
        });

        eg_h(&config.h_e, &v).to_string()
    }

    /// Generates a selection hash (Equation 95)
    ///
    /// ψ_i = H(H_E;40,λ_i,K,α_1,β_1,α_2,β_2 ...,α_m,β_m),
    ///
    pub fn generate_contest_hash(
        config: &EncryptedBallotConfig,
        contest_label: &String,
        selections: &Vec<PreEncryptedContestSelection>,
    ) -> String {
        let mut v = vec![0x41];

        v.extend_from_slice(contest_label.as_bytes());
        v.extend_from_slice(config.election_public_key.0.to_bytes_be().as_slice());

        // TODO: Check if this sorting works
        let mut sorted_selection_hashes = selections
            .iter()
            .map(|s| s.get_crypto_hash())
            .collect::<Vec<&String>>();
        sorted_selection_hashes.sort();

        sorted_selection_hashes.iter().for_each(|s| {
            v.extend(hex_to_bytes(s));
        });

        eg_h(&config.h_e, &v).to_string()
    }

    /// Generates a nonce for deterministic ballot encryption (Equation 96)
    ///
    /// H(B) = H(H_E;42,χ_1,χ_2,...,χ_m ,B_aux)
    ///
    pub fn generate_confirmation_code(
        config: &EncryptedBallotConfig,
        contests: &Vec<PreEncryptedContest>,
        b_aux: &[u8],
    ) -> String {
        let mut v = vec![0x42];

        contests.iter().for_each(|c| {
            v.extend(hex_to_bytes(&c.crypto_hash));
        });

        v.extend_from_slice(b_aux);
        eg_h(&config.h_e, &v).to_string()
    }

    /// Generates a nonce for deterministic ballot encryption (Equation 97)
    ///
    /// ξ_(i,j,k) = H(H_E;43,ξ,Λ_i,λ_j,λ_k) mod q
    ///
    pub fn generate_nonce(
        config: &EncryptedBallotConfig,
        primary_nonce: &[u8],
        label_i: &[u8],
        label_j: &[u8],
        label_k: &[u8],
        fixed_parameters: &FixedParameters,
    ) -> BigUint {
        let mut v = vec![0x43];

        v.extend_from_slice(primary_nonce);
        v.extend_from_slice(label_i);
        v.extend_from_slice(label_j);
        v.extend_from_slice(label_k);

        let nonce = eg_h(&config.h_e, &v);
        BigUint::from_bytes_be(nonce.0.as_slice()) % fixed_parameters.q.as_ref()
    }
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
