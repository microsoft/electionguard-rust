use crate::{
    ballot::BallotConfig,
    contest::ContestEncrypted,
    hash::{eg_h, HValue},
};

/// Confirmation code for an encrypted ballot (Equation 59)
///
/// H(B) = H(H_E;24,χ_1,χ_2,...,χ_{m_B} ,B_aux).
///
pub fn encrypted(config: &BallotConfig, contests: &Vec<ContestEncrypted>, b_aux: &[u8]) -> HValue {
    let mut v = vec![0x24];

    contests.iter().for_each(|c| {
        v.extend(c.crypto_hash.as_ref());
    });

    v.extend_from_slice(b_aux);
    eg_h(&config.h_e, &v)
}
