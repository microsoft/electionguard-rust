use base64::{engine::general_purpose, Engine as _};
use num_bigint::BigUint;

use crate::{
    ballot::BallotConfig,
    fixed_parameters::FixedParameters,
    hash::{eg_h, eg_h_js, HValue},
};

// pub struct Nonce {}

/// Generates a nonce for encrypted ballots (Equation 22)
///
///  ξi,j = H(H_E;20,ξ_B,Λ_i,λ_j)
/// TODO: Check if mod q?
///
pub fn encrypted(h_e: &[u8], primary_nonce: &[u8], label_i: &[u8], label_j: &[u8]) -> String {
    let mut v = vec![0x20];

    v.extend_from_slice(primary_nonce);
    v.extend_from_slice(label_i);
    v.extend_from_slice(label_j);

    eg_h_js(&h_e, &v)
}
