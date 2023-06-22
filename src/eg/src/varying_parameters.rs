// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// The parameters for a specific election.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaryingParameters {
    /// Number of guardians.
    pub n: u16, // Two bytes in the parameter base hash H_P.

    /// Decryption quorum threshold value.
    pub k: u16, // Two bytes in the parameter base hash H_P.

    /// Date string.
    pub date: String,

    // Jurisdictional information string.
    pub info: String,
}

impl VaryingParameters {
    /// Verifies the `VaryingParameters` meet some basic validity requirements.
    #[allow(clippy::nonminimal_bool)]
    pub fn verify(&self) -> Result<()> {
        // `n` must be greater than or equal to 1
        if !(1 <= self.n) {
            bail!("Varying parameters failed check: 1 <= n");
        }

        // `k` must be greater than or equal to 1
        if !(1 <= self.k) {
            bail!("Varying parameters failed check: 1 <= k");
        }

        // `k` must be less than or equal to `n`
        if !(self.k <= self.n) {
            bail!("Varying parameters failed check: k <= n");
        }

        Ok(())
    }
}
