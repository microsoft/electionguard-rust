// Copyright (C) Microsoft Corporation. All rights reserved.

use std::collections::HashSet;

use anyhow::Result;
use eg::ballot_style::BallotStyle;
use eg::election_record::PreVotingData;
use eg::hash::{eg_h, HValue, HVALUE_BYTE_LEN};
use eg::joint_election_public_key::{Ciphertext, JointElectionPublicKey};
use eg::vec1::Vec1;
use util::csprng::Csprng;
use util::logging::Logging;

use crate::ballot::BallotPreEncrypted;
use crate::contest::ContestPreEncrypted;

pub struct BallotEncryptingTool {
    /// The pre-voting data.
    pub pv_data: PreVotingData,

    /// The ballot style to generate a ballot for.
    pub ballot_style: BallotStyle,

    /// Encryption key used to encrypt the primary nonce.
    pub encryption_key: Option<JointElectionPublicKey>,
}

pub struct EncryptedNonce {
    pub encrypted_nonce: Ciphertext,
}

impl BallotEncryptingTool {
    pub fn new(
        header: PreVotingData,
        ballot_style: BallotStyle,
        encryption_key: Option<JointElectionPublicKey>,
    ) -> Self {
        Self {
            pv_data: header,
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
        ballot.contests.indices().for_each(|i| {
            Logging::log(
                tag,
                &format!("    {:?}", ballot.contests.get(i).unwrap().contest_hash),
                line!(),
                file!(),
            );
        });
    }

    pub fn generate_ballots(
        &self,
        csprng: &mut Csprng,
        num_ballots: usize,
    ) -> (Vec<BallotPreEncrypted>, Vec<HValue>) {
        let mut ballots = Vec::new();
        let mut primary_nonces = Vec::new();

        while ballots.len() < num_ballots {
            let (ballot, nonce) =
                BallotPreEncrypted::new(&self.pv_data, &self.ballot_style, csprng, false);
            if Self::are_unique_shortcodes(&ballot.contests) {
                ballots.push(ballot);
                primary_nonces.push(nonce);
            }
        }

        (ballots, primary_nonces)
    }

    /// Writes a list of confirmation codes to a file.
    pub fn metadata_to_stdiowrite(
        &self,
        codes: &Vec<HValue>,
        stdiowrite: &mut dyn std::io::Write,
    ) -> Result<()> {
        stdiowrite.write_fmt(format_args!(
            "{}\n",
            codes
                .iter()
                .map(|cc| cc.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        ))?;
        Ok(())
    }

    /// Returns the last byte of the hash value as a two digit hex.
    pub fn short_code_last_byte(full_hash: &HValue) -> String {
        format!("{:02x}", full_hash.0[HVALUE_BYTE_LEN - 1])
    }

    /// Generates a selection hash (Equation 93/94)
    ///
    /// ψ_i = H(H_E;40,[λ_i],K,α_1,β_1,α_2,β_2 ...,α_m,β_m),
    ///
    /// TODO: Remove label from the hash (equation 93)
    pub fn selection_hash(header: &PreVotingData, selections: &Vec1<Ciphertext>) -> HValue {
        let mut v = vec![0x40];

        v.extend_from_slice(header.public_key.0.to_bytes_be().as_slice());

        selections.indices().for_each(|i| {
            let s = selections.get(i).unwrap();
            v.extend_from_slice(s.alpha.to_bytes_be().as_slice());
            v.extend_from_slice(s.beta.to_bytes_be().as_slice());
        });

        eg_h(&header.hashes_ext.h_e, &v)
    }

    /// Returns true iff all shortcodes within each preencrypted contest on a ballot are unique
    pub fn are_unique_shortcodes(contests: &Vec1<ContestPreEncrypted>) -> bool {
        contests
            .indices()
            .map(|i| {
                let c = contests.get(i).unwrap();
                let shortcodes: HashSet<String> = HashSet::from_iter(
                    c.selections
                        .indices()
                        .map(|j| c.selections.get(j).unwrap().shortcode.clone()),
                );
                shortcodes.len() == contests.get(i).unwrap().selections.len()
            })
            .all(|x| x)
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
