use eg::{
    ballot::BallotConfig,
    hash::{eg_h, hex_to_bytes},
};

use crate::contest::ContestPreEncrypted;

/// Confirmation code for a pre-encrypted ballot (Equation 96)
///
/// H(B) = H(H_E;42,χ_1,χ_2,...,χ_m ,B_aux)
///
pub fn confirmation_code(
    config: &BallotConfig,
    contests: &Vec<ContestPreEncrypted>,
    b_aux: &[u8],
) -> String {
    let mut v = vec![0x42];

    contests.iter().for_each(|c| {
        v.extend(hex_to_bytes(&c.crypto_hash));
    });

    v.extend_from_slice(b_aux);
    eg_h(&config.h_e, &v).to_string()
}
