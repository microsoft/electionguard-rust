use eg::hash::{eg_h, HValue};

use crate::contest::ContestPreEncrypted;

/// Confirmation code for a pre-encrypted ballot (Equation 96)
///
/// H(B) = H(H_E;42,χ_1,χ_2,...,χ_m ,B_aux)
///
pub fn confirmation_code(
    h_e: &HValue,
    contests: &Vec<ContestPreEncrypted>,
    b_aux: &[u8],
) -> HValue {
    let mut v = vec![0x42];

    contests.iter().for_each(|c| {
        v.extend(c.crypto_hash.as_ref());
    });

    v.extend_from_slice(b_aux);
    eg_h(&h_e, &v)
}
