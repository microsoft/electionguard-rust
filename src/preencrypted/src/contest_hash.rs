// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use eg::{
    election_manifest::ContestIndex,
    pre_voting_data::PreVotingData,
    hash::{eg_h, HValue},
    vec1::Vec1,
};

use crate::contest_selection::ContestSelectionPreEncrypted;

/// Contest hash for pre-encrypted ballots (Equation 95) [TODO fix ref]
///
/// ψ_i = H(H_E;40,λ_i,K,α_1,β_1,α_2,β_2 ...,α_m,β_m),
///
pub fn contest_hash(
    pvd: &PreVotingData,
    contest_ix: ContestIndex,
    selections: &Vec1<ContestSelectionPreEncrypted>,
) -> HValue {
    let group = &pvd.election_parameters().fixed_parameters().group();

    let mut v = vec![0x41];

    v.extend_from_slice(contest_ix.get_one_based_4_be_bytes());
    v.extend_from_slice(
        pvd
            .public_key
            .joint_public_key
            .to_be_bytes_left_pad(group)
            .as_slice(),
    );

    // TODO: Check if this sorting works
    let mut sorted_selection_hashes = selections
        .indices()
        .map(|i| {
            #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
            selections.get(i).unwrap().selection_hash
        })
        .collect::<Vec<HValue>>();
    sorted_selection_hashes.sort();

    sorted_selection_hashes.iter().for_each(|s| {
        v.extend(s.as_ref());
    });

    eg_h(&pvd.h_e(), &v)
}
