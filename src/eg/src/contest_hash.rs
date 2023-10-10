// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use crate::{
    // contest_selection::ContestSelectionCiphertext,
    election_record::PreVotingData,
    hash::{eg_h, HValue},
    joint_election_public_key::Ciphertext,
};

/// Contest hash for encrypted ballots (Equation 58)
///
/// χl = H(H_E;23,Λ_l,K,α_1,β_1,α_2,β_2 ...,α_m,β_m),
///
pub fn contest_hash(header: &PreVotingData, contest_label: &String, vote: &[Ciphertext]) -> HValue {
    let mut v = vec![0x23];

    v.extend_from_slice(contest_label.as_bytes());
    v.extend_from_slice(
        header
            .public_key
            .joint_election_public_key
            .to_bytes_be()
            .as_slice(),
    );

    vote.iter().for_each(|vote_i| {
        v.extend_from_slice(vote_i.alpha.to_bytes_be().as_slice());
        v.extend_from_slice(vote_i.beta.to_bytes_be().as_slice());
    });

    eg_h(&header.hashes_ext.h_e, &v)
}
