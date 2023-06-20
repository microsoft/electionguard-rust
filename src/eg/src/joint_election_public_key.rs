// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use num_bigint::BigUint;
use num_traits::One;

use crate::{fixed_parameters::FixedParameters, key::PublicKey};

pub struct JointElectionPublicKey(pub BigUint);

impl JointElectionPublicKey {
    pub fn compute(fixed_parameters: &FixedParameters, guardian_public_keys: &[PublicKey]) -> Self {
        Self(
            guardian_public_keys
                .iter()
                .fold(BigUint::one(), |acc, public_key| {
                    let k0 = public_key.public_key_k0();
                    acc.modpow(k0, fixed_parameters.p.as_ref())
                }),
        )
    }

    /// Returns the `JointElectionPublicKey` as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_len_p(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        fixed_parameters.biguint_to_be_bytes_len_p(&self.0)
    }
}
