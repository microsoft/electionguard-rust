use crate::{
    ballot::BallotConfig,
    contest_selection::ContestSelectionPreEncrypted,
    hash::{eg_h, hex_to_bytes},
};

pub struct ContestHash {}

impl ContestHash {
    /// Generates a selection hash (Equation 95)
    ///
    /// ψ_i = H(H_E;40,λ_i,K,α_1,β_1,α_2,β_2 ...,α_m,β_m),
    ///
    pub fn pre_encrypted(
        config: &BallotConfig,
        contest_label: &String,
        selections: &Vec<ContestSelectionPreEncrypted>,
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
}
