// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]


use util::algebra::FieldElement;

use crate::{
    election_manifest::{ContestIndex, ContestOptionIndex},
    election_record::PreVotingData,
    hash::eg_h,
};

/// Generates a nonce for encrypted ballots (Equation 22)
///
///  ξi,j = H(H_E;20,ξ_B,Λ_i,λ_j)
/// TODO: Check if mod q?
///
pub fn encrypted(
    header: &PreVotingData,
    primary_nonce: &[u8],
    label_i: ContestIndex,
    label_j: ContestOptionIndex,
) -> FieldElement {
    let field = &header.parameters.fixed_parameters.field;
    let mut v = vec![0x20];

    v.extend_from_slice(primary_nonce);
    v.extend_from_slice(&label_i.get_one_based_u32().to_be_bytes());
    v.extend_from_slice(&label_j.get_one_based_u32().to_be_bytes());

    let nonce = eg_h(&header.hashes_ext.h_e, &v);
    FieldElement::from_bytes_be(nonce.0.as_slice(), field)
}
