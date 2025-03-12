// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

use crate::{
    ballot::HValue_H_I,
    ciphertext::Ciphertext,
    election_manifest::ContestIndex,
    hash::{HValue, eg_h},
    pre_voting_data::PreVotingData,
};

//=================================================================================================|

/// EG DS v2.1.0 sec 3.4.1 Contest hash
///
/// Eq 70:
///
/// χl = H(H_I; 0x28, l, α_1, β_1, α_2, β_2 ..., α_m, β_m, C_0, ..., C_n),
///
pub fn contest_hash_chi_l(
    pre_voting_data: &PreVotingData,
    h_i: &HValue_H_I,
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

    // EGDS v2.1.0 pg. 76 §3.4.1 (70)
    let expected_len =
        69 + (2 * ciphertexts.len() + 1) * 512 + encrypted_contest_data_blocks.len() * 32;
    let expected_len2 =
        5 + (2 * ciphertexts.len()) * 512 + encrypted_contest_data_blocks.len() * 32;
    debug!("expected_len: {expected_len}");
    debug!("expected_len2: {expected_len2}");

    let mut v = Vec::<u8>::with_capacity(expected_len);
    v.push(0x28);
    v.extend_from_slice(&contest_ix.get_one_based_u32().to_be_bytes());

    debug!("there are {} ciphertexts", ciphertexts.len());

    ciphertexts.iter().for_each(|contest_data_field_ct| {
        debug!(
            "before alpha: len is {} mod 512 = {}",
            v.len(),
            v.len() % 512
        );
        v.extend_from_slice(
            contest_data_field_ct
                .alpha
                .to_be_bytes_left_pad(group)
                .as_slice(),
        );
        debug!(
            "before beta: len is {} mod 512 = {}",
            v.len(),
            v.len() % 512
        );
        v.extend_from_slice(
            contest_data_field_ct
                .beta
                .to_be_bytes_left_pad(group)
                .as_slice(),
        );
    });
    debug!(
        "after ciphertexts: len is {} mod 512 = {}",
        v.len(),
        v.len() % 512
    );

    debug!(
        "there are {} encrypted_contest_data_blocks",
        encrypted_contest_data_blocks.len()
    );

    encrypted_contest_data_blocks.iter().for_each(|block| {
        debug!(
            "len before data block: len is {} mod 32 = {}",
            v.len(),
            v.len() % 32
        );
        v.extend_from_slice(&block.0);
    });
    debug!(
        "len after data blocks: len is {} mod 32 = {}",
        v.len(),
        v.len() % 32
    );

    if v.len() == expected_len {
        info!(
            "len after data blocks: len is {} == expected_len of {}",
            v.len(),
            expected_len
        );
    } else {
        warn!(
            "len after data blocks: len is {} != expected_len of {}",
            v.len(),
            expected_len
        );
    }
    if v.len() == expected_len2 {
        info!(
            "len after data blocks: len is {} == expected_len2 of {}",
            v.len(),
            expected_len2
        );
    } else {
        warn!(
            "len after data blocks: len is {} != expected_len2 of {}",
            v.len(),
            expected_len2
        );
    }
    assert_eq!(v.len(), expected_len2);

    eg_h(h_i, &v)
}
