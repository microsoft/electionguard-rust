// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{fixed_parameters::FixedParameters, varying_parameters::VaryingParameters};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
