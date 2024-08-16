// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use crate::{
    contest_encrypted::ContestDataFieldsCiphertexts,
    hash::{eg_h, HValue},
    pre_voting_data::PreVotingData,
};

/// Confirmation code for an encrypted ballot (Equation 59)
///
/// H(B) = H(H_E; 0x24, χ_1, χ_2, ..., χ_{m_B}, B_{aux})
///
pub fn compute_confirmation_code<'a>(
    pre_voting_data: &PreVotingData,
    contests_fields_ciphertexts: impl Iterator<Item = &'a ContestDataFieldsCiphertexts>,
    opt_b_aux: Option<&[u8]>,
) -> HValue {
    let b_aux = opt_b_aux.unwrap_or(&[0u8; 0]);

    let h_e = &pre_voting_data.hashes_ext.h_e;

    let mut v = vec![0x24];

    for item in contests_fields_ciphertexts {
        v.extend(item.contest_hash.as_ref());
    }

    v.extend_from_slice(b_aux);

    eg_h(h_e, &v)
}
