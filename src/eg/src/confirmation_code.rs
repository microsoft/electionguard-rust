// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use crate::{
    contest_encrypted::ContestEncrypted,
    hash::{eg_h, HValue},
};

/// Confirmation code for an encrypted ballot (Equation 59)
///
/// H(B) = H(H_E;24,χ_1,χ_2,...,χ_{m_B} ,B_aux).
///
pub fn confirmation_code<'a>(
    h_e: &HValue,
    contests: impl Iterator<Item = &'a ContestEncrypted>,
    b_aux: &[u8],
) -> HValue {
    let mut v = vec![0x24];

    for item in contests {
        v.extend(item.contest_hash.as_ref());
    }

    v.extend_from_slice(b_aux);
    eg_h(h_e, &v)
}
