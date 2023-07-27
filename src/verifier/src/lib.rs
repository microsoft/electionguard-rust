// use wasm_bindgen::prelude::*;

// use crate::{
//     election_parameters::ElectionParameters, hash::HVALUE_BYTE_LEN, hashes::Hashes,
//     nizk::ProofGuardian, nonce::encrypted, voter::VoterVerificationCode,
// };

// use base64::{engine::general_purpose, Engine as _};

use eg::{
    ballot::BallotEncrypted,
    contest_encrypted::{ContestEncrypted, ContestEncryptedIndex},
    election_manifest::ContestIndex,
    election_record::PreVotingData,
};

pub struct Verifier {
    header: PreVotingData,
}

impl Verifier {
    pub fn new(header: PreVotingData) -> Self {
        Verifier { header }
    }

    /// Verification 1: Parameter Validation
    pub fn verification_one(&self) -> bool {
        todo!()
    }

    pub fn verify_ballot_validity(&self, ballot: &BallotEncrypted) -> bool {
        let mut valid: bool = true;

        // for (i, contest) in ballot.contests().iter().enumerate() {
        // for i in 1..ballot.contests().len() + 1 {
        ballot.contests().indices().for_each(|i| {
            let contest = ballot.contests().get(i).unwrap();
            let c_idx = ContestEncryptedIndex::from_one_based_index(i.get_one_based_usize() as u32)
                .unwrap();
            // Verify proof of ballot correctness
            // for (j, proof) in
            let proofs_ballot_correctness = ballot
                .contests()
                .get(c_idx)
                .unwrap()
                .get_proof_ballot_correctness();

            proofs_ballot_correctness.indices().for_each(|j| {
                valid &= proofs_ballot_correctness.get(j).unwrap().verify(
                    &self.header,
                    &contest.selection[j.get_zero_based_usize()],
                    1 as usize,
                );
            });

            // Verify proof of satisfying the selection limit
            let ct_combined = ContestEncrypted::sum_selection_vector(
                &self.header.parameters.fixed_parameters,
                &contest.selection,
            );
            valid &= contest.get_proof_selection_limit().verify(
                &self.header,
                &ct_combined,
                self.header
                    .manifest
                    .contests
                    .get(
                        ContestIndex::from_one_based_index(i.get_one_based_usize() as u32).unwrap(),
                    )
                    .unwrap()
                    .selection_limit,
            );

            // println!("  Verified proofs for contest {}", i,);
        });

        valid
    }
}

// impl Verifier {
//     pub fn new(election_parameters: ElectionParameters, hashes: Hashes) -> Self {
//         Verifier {
//             election_parameters,
//             hashes,
//         }
//     }

//     /// Verification 1: Parameter Validation
//     pub fn verification_one(&self) -> bool {
//         todo!()
//     }

//     /// Verification 2: Guardian Public Key Validation
//     pub fn verification_two(&self, proofs: &Vec<ProofGuardian>) -> bool {
//         for (i, proof) in proofs.iter().enumerate() {
//             if !proof.verify(
//                 &self.election_parameters.fixed_parameters,
//                 self.hashes.h_p,
//                 i as u16,
//                 self.election_parameters.varying_parameters.k,
//             ) {
//                 return false;
//             }
//         }
//         false
//     }
// }

// #[wasm_bindgen]
// pub fn eg_qrcode_parse(code_data: &[u8]) -> String {
//     serde_json::to_string(&VoterVerificationCode {
//         pn: general_purpose::URL_SAFE_NO_PAD.encode(code_data[0..HVALUE_BYTE_LEN].to_vec()),
//         cc: general_purpose::URL_SAFE_NO_PAD
//             .encode(code_data[HVALUE_BYTE_LEN..2 * HVALUE_BYTE_LEN].to_vec()),
//         vs: String::from(""),
//     })
//     .unwrap()
// }

// #[wasm_bindgen]
// pub fn eg_nonce_selection(h_e: &[u8], pn: &[u8], label_i: &[u8], label_j: &[u8]) -> String {
//     encrypted(&h_e, pn, label_i, label_j)
// }

// // pub fn set_panic_hook() {
//     // When the `console_error_panic_hook` feature is enabled, we can call the
//     // `set_panic_hook` function at least once during initialization, and then
//     // we will get better error messages if our code ever panics.
//     //
//     // For more details see
//     // https://github.com/rustwasm/console_error_panic_hook#readme
//     #[cfg(feature = "console_error_panic_hook")]
//     console_error_panic_hook::set_once();
// // }

// mod utils;

// use base64::{engine::general_purpose, Engine as _};
// use eg::{contest_selection::ContestSelection, hash::HValue, nonce::encrypted};
// use wasm_bindgen::prelude::*;

// // When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// // allocator.
// #[cfg(feature = "wee_alloc")]
// #[global_allocator]
// static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// #[wasm_bindgen]
// extern "C" {
//     fn alert(s: &str);
// }
