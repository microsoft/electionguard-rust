use crate::{
    ballot::BallotConfig,
    contest_selection::ContestSelectionCiphertext,
    hash::{eg_h, HValue},
};

/// Contest hash for encrypted ballots (Equation 58)
///
/// χl = H(H_E;23,Λ_l,K,α_1,β_1,α_2,β_2 ...,α_m,β_m),
///
pub fn encrypted(
    config: &BallotConfig,
    contest_label: &String,
    vote: &Vec<ContestSelectionCiphertext>,
) -> HValue {
    let mut v = vec![0x23];

    v.extend_from_slice(contest_label.as_bytes());
    v.extend_from_slice(config.election_public_key.0.to_bytes_be().as_slice());

    vote.iter().for_each(|x| {
        v.extend_from_slice(x.ciphertext.alpha.to_bytes_be().as_slice());
        v.extend_from_slice(x.ciphertext.beta.to_bytes_be().as_slice());
    });

    eg_h(&config.h_e, &v)
}
