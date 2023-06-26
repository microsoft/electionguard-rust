use num_bigint::BigUint;

use crate::{election_record::ElectionRecordHeader, hash::eg_h};

/// Generates a nonce for encrypted ballots (Equation 22)
///
///  ξi,j = H(H_E;20,ξ_B,Λ_i,λ_j)
/// TODO: Check if mod q?
///
pub fn encrypted(
    header: &ElectionRecordHeader,
    primary_nonce: &[u8],
    label_i: &[u8],
    label_j: &[u8],
) -> BigUint {
    let mut v = vec![0x20];

    v.extend_from_slice(primary_nonce);
    v.extend_from_slice(label_i);
    v.extend_from_slice(label_j);

    let nonce = eg_h(&header.hashes_ext.h_e, &v);

    BigUint::from_bytes_be(nonce.0.as_slice()) % header.parameters.fixed_parameters.q.as_ref()
}
