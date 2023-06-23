// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};

use crate::{fixed_parameters::FixedParameters, key::GuardianPublicKey};

/// The joint election public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointElectionPublicKey(
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub BigUint,
);

impl JointElectionPublicKey {
    pub fn compute(
        fixed_parameters: &FixedParameters,
        guardian_public_keys: &[GuardianPublicKey],
    ) -> Self {
        //? TODO: Would it be useful to parallelize this?
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
