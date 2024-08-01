// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use util::csprng::Csprng;

use crate::{
    fixed_parameters::FixedParameters, serialize::SerializablePretty,
    varying_parameters::VaryingParameters,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionParameters {
    /// The fixed ElectionGuard parameters that apply to all elections.
    pub fixed_parameters: FixedParameters,

    /// The parameters for a specific election.
    pub varying_parameters: VaryingParameters,
}

impl ElectionParameters {
    /// Reads a `ElectionParameters` from a `std::io::Read` and validates it.
    pub fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        csprng: &mut Csprng,
    ) -> Result<Self> {
        let self_: Self =
            serde_json::from_reader(stdioread).context("Reading ElectionParameters")?;

        self_.validate(csprng)?;

        Ok(self_)
    }

    /// Verifies that the `ElectionParameters` meet some basic validity requirements.
    pub fn validate(&self, csprng: &mut Csprng) -> Result<()> {
        self.fixed_parameters.validate(csprng)?;
        self.varying_parameters.validate()?;
        Ok(())
    }

    /// Reads an `ElectionParameters` from a byte sequence.
    pub fn from_bytes(bytes: &[u8]) -> Result<ElectionParameters> {
        serde_json::from_slice(bytes).with_context(|| "Error parsing ElectionParameters bytes")
    }
}

impl SerializablePretty for ElectionParameters {}
