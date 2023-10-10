// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use eg::{
    election_manifest::{ContestIndex, ContestOptionIndex},
    election_record::PreVotingData,
    hash::eg_h,
};
use num_bigint::BigUint;

// impl Nonce {
/// Generates a nonce for pre-encrypted ballots (Equation 97)
///
/// ξ_(i,j,k) = H(H_E;0x43,ξ,ind_c(Λ_i),ind_o(λ_j),ind_o(λ_k)). mod q
///
pub fn option_nonce(
    header: &PreVotingData,
    primary_nonce: &[u8],
    index_i: ContestIndex,
    index_j: ContestOptionIndex,
    index_k: ContestOptionIndex,
) -> BigUint {
    let mut v = vec![0x43];

    v.extend_from_slice(primary_nonce);
    v.extend_from_slice(index_i.get_one_based_u32().to_be_bytes().as_slice());
    v.extend_from_slice(index_j.get_one_based_u32().to_be_bytes().as_slice());
    v.extend_from_slice(index_k.get_one_based_u32().to_be_bytes().as_slice());

    let nonce = eg_h(&header.hashes_ext.h_e, &v);
    BigUint::from_bytes_be(nonce.0.as_slice()) % header.parameters.fixed_parameters.q.as_ref()
}
