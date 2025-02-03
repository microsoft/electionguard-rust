// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use crate::{
    ciphertext::Ciphertext,
    election_manifest::ContestIndex,
    hash::{eg_h, HValue},
    // contest_selection::ContestSelectionCiphertext,
    pre_voting_data::PreVotingData,
};

/// EG DS v2.1.0 sec 3.4.1 Contest hash
///
/// Eq 70:
///
/// χl = H(H_I; 0x28, l, α_1, β_1, α_2, β_2 ..., α_m, β_m, C_0, ..., C_n),
///
pub fn contest_hash_chi_l(
    pre_voting_data: &PreVotingData,
    contest_ix: ContestIndex,
    ciphertexts: &[Ciphertext],
    encrypted_contest_data_blocks: &[HValue],
) -> HValue {
    let group = pre_voting_data
        .election_parameters()
        .fixed_parameters()
        .group();

    // B1 = 0x28 | b(one based contest index, 4) | b(alpha_1, 512) | · · · | b(beta_m, 512)
    // b(C0, 32) | ... | b(C_n, 32)
    let expected_len =
        1 + 4 + 512 * 2 * ciphertexts.len() + 32 * encrypted_contest_data_blocks.len();

    let mut v = Vec::<u8>::with_capacity(expected_len);
    v.push(0x28);
    v.extend_from_slice(&contest_ix.get_one_based_u32().to_be_bytes());
    v.extend_from_slice(
        pre_voting_data
            .jvepk_k()
            .group_element
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

    encrypted_contest_data_blocks.iter().for_each(|block| {
        v.extend_from_slice(&block.0);
    });

    assert_eq!(v.len(), expected_len);

    let expected_len =
        69 + (2 * ciphertexts.len() + 1) * 512 + encrypted_contest_data_blocks.len() * 32; // EGDS 2.1.0 pg. 76 (70)
    assert_eq!(v.len(), expected_len);

    eg_h(pre_voting_data.h_e(), &v)
}
