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
    let expected_len_errata =
        69 + (2 * ciphertexts.len() + 1) * 512 + encrypted_contest_data_blocks.len() * 32;
    let expected_len = 5 + (2 * ciphertexts.len()) * 512 + encrypted_contest_data_blocks.len() * 32;
    trace!("expected_len: {expected_len_errata}");
    trace!("expected_len2: {expected_len}");

    let mut v = Vec::<u8>::with_capacity(expected_len_errata);
    v.push(0x28);
    v.extend_from_slice(&contest_ix.get_one_based_u32().to_be_bytes());

    trace!(
        "Contest hash input msg involves {} ciphertexts",
        ciphertexts.len()
    );

    ciphertexts.iter().for_each(|contest_data_field_ct| {
        trace!(
            "Contest hash input msg len before alpha is {} mod 512 = {}",
            v.len(),
            v.len() % 512
        );
        v.extend_from_slice(
            contest_data_field_ct
                .alpha
                .to_be_bytes_left_pad(group)
                .as_slice(),
        );
        trace!(
            "Contest hash input msg len before beta is {} mod 512 = {}",
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
    trace!(
        "Contest hash input msg len after ciphertexts is {} mod 512 = {}",
        v.len(),
        v.len() % 512
    );

    trace!(
        "there are {} encrypted_contest_data_blocks",
        encrypted_contest_data_blocks.len()
    );

    encrypted_contest_data_blocks.iter().for_each(|block| {
        trace!(
            "Contest hash input msg len before data block is {} mod 32 = {}",
            v.len(),
            v.len() % 32
        );
        v.extend_from_slice(&block.0);
    });
    trace!(
        "Contest hash input msg len after data blocks is {} mod 32 = {}",
        v.len(),
        v.len() % 32
    );

    if v.len() == expected_len {
        trace!(
            "Contest hash input msg len after data blocks is {} == expected_len of {}",
            v.len(),
            expected_len_errata
        );
    } else {
        warn!(
            "Contest hash input msg len after data blocks is {} != expected_len of {}",
            v.len(),
            expected_len_errata
        );
    }
    if v.len() == expected_len {
        trace!(
            "Contest hash input msg len after data blocks is {} == expected_len2 of {}",
            v.len(),
            expected_len
        );
    } else {
        warn!(
            "Contest hash input msg len after data blocks is {} != expected_len2 of {}",
            v.len(),
            expected_len
        );
    }
    assert_eq!(v.len(), expected_len);

    eg_h(h_i, &v)
}
