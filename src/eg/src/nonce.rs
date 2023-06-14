use num_bigint::BigUint;

use crate::{ballot::BallotConfig, fixed_parameters::FixedParameters, hash::eg_h};

pub struct Nonce {}

impl Nonce {
    /// Generates a nonce for pre-encrypted deterministic ballot encryption (Equation 97)
    ///
    /// ξ_(i,j,k) = H(H_E;43,ξ,Λ_i,λ_j,λ_k) mod q
    ///
    pub fn pre_encrypted(
        config: &BallotConfig,
        primary_nonce: &[u8],
        label_i: &[u8],
        label_j: &[u8],
        label_k: &[u8],
        fixed_parameters: &FixedParameters,
    ) -> BigUint {
        let mut v = vec![0x43];

        v.extend_from_slice(primary_nonce);
        v.extend_from_slice(label_i);
        v.extend_from_slice(label_j);
        v.extend_from_slice(label_k);

        let nonce = eg_h(&config.h_e, &v);
        BigUint::from_bytes_be(nonce.0.as_slice()) % fixed_parameters.q.as_ref()
    }
}
