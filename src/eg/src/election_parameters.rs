// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{Context, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{fixed_parameters::FixedParameters, varying_parameters::VaryingParameters};

#[derive(Debug, Serialize, Deserialize)]
pub struct ElectionParameters {
    /// The fixed ElectionGuard parameters that apply to all elections.
    pub fixed_parameters: FixedParameters,

    /// The parameters for a specific election.
    pub varying_parameters: VaryingParameters,
}

impl ElectionParameters {
    /// Reads an `ElectionParameters` from a byte sequence.
    pub fn from_bytes(bytes: &[u8]) -> Result<ElectionParameters> {
        serde_json::from_slice(bytes).with_context(|| "Error parsing ElectionParameters bytes")
    }

    /// Returns a pretty JSON `String` representation of the `ElectionParameters`.
    /// The final line will end with a newline.
    pub fn to_json(&self) -> String {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }

    /// Converts a `BigUint` to a big-endian byte array of the correct length for `mod p`.
    pub fn biguint_to_be_bytes_len_p(&self, u: &BigUint) -> Vec<u8> {
        self.fixed_parameters.biguint_to_be_bytes_len_p(u)
    }

    /// Converts a `BigUint` to a big-endian byte array of the correct length for `mod q`.
    pub fn biguint_to_be_bytes_len_q(&self, u: &BigUint) -> Vec<u8> {
        self.fixed_parameters.biguint_to_be_bytes_len_q(u)
    }
}
