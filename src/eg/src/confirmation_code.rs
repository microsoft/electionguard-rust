use crate::{
    contest_encrypted::ContestEncrypted,
    hash::{eg_h, HValue},
    vec1::Vec1,
};

/// Confirmation code for an encrypted ballot (Equation 59)
///
/// H(B) = H(H_E;24,χ_1,χ_2,...,χ_{m_B} ,B_aux).
///
pub fn confirmation_code(h_e: &HValue, contests: &Vec1<ContestEncrypted>, b_aux: &[u8]) -> HValue {
    let mut v = vec![0x24];

    contests.indices().for_each(|i| {
        v.extend(contests.get(i).unwrap().contest_hash.as_ref());
    });

    v.extend_from_slice(b_aux);
    eg_h(h_e, &v)
}
