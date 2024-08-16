// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use crate::{
    ciphertext::Ciphertext,
    election_manifest::ContestIndex,
    hash::{eg_h, HValue},
    // contest_selection::ContestSelectionCiphertext,
    pre_voting_data::PreVotingData,
};

/// Design Specification v2.0
///
/// 3.4.1 Contest hash
///
/// Equation 57:
///
/// χl = H(H_E; 0x23, Λ_l, K, α_1, β_1, α_2, β_2 ..., α_m, β_m),
///
pub fn contest_hash_chi_l(
    pre_voting_data: &PreVotingData,
    contest_ix: ContestIndex,
    //ciphertexts: &[Ciphertext],
    ciphertexts: &[Ciphertext],
) -> HValue {
    let group = &pre_voting_data.parameters.fixed_parameters.group;

    // B1 = 0x23 | b(one based contest index, 4) | b(K, 512) | b(alpha_1, 512) | · · · | b(beta_m, 512)
    let expected_len = 1 + 4 + 512 + 512 * 2 * ciphertexts.len();

    let mut v = Vec::<u8>::with_capacity(expected_len);
    v.push(0x23);
    v.extend_from_slice(&contest_ix.get_one_based_u32().to_be_bytes());
    v.extend_from_slice(
        pre_voting_data
            .public_key
            .joint_election_public_key
            .to_be_bytes_left_pad(group)
            .as_slice(),
    );

    ciphertexts.iter().for_each(|contest_data_field_ct| {
        v.extend_from_slice(
            contest_data_field_ct
                .alpha
                .to_be_bytes_left_pad(group)
                .as_slice(),
        );
        v.extend_from_slice(
            contest_data_field_ct
                .beta
                .to_be_bytes_left_pad(group)
                .as_slice(),
        );
    });

    debug_assert_eq!(v.len(), expected_len);

    eg_h(&pre_voting_data.hashes_ext.h_e, &v)
}
