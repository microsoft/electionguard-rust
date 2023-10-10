// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use eg::{
    hash::{eg_h, HValue},
    vec1::Vec1,
};

use crate::contest::ContestPreEncrypted;

/// Confirmation code for a pre-encrypted ballot (Equation 96)
///
/// H(B) = H(H_E;42,χ_1,χ_2,...,χ_m ,B_aux)
///
pub fn confirmation_code(
    h_e: &HValue,
    contests: &Vec1<ContestPreEncrypted>,
    b_aux: &[u8],
) -> HValue {
    let mut v = vec![0x42];

    contests.indices().for_each(|i| {
        #[allow(clippy::unwrap_used)] //? TODO: Remove temp development code
        v.extend(contests.get(i).unwrap().contest_hash.as_ref());
    });

    v.extend_from_slice(b_aux);
    eg_h(h_e, &v)
}
