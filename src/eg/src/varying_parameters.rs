// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::guardian::GuardianIndex;

/// Ballot chaining.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BallotChaining {
    Prohibited,
    Allowed,
    Required,
}

/// The parameters for a specific election.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaryingParameters {
    /// Number of guardians.
    pub n: GuardianIndex,

    /// Decryption quorum threshold value.
    pub k: GuardianIndex,

    /// Date string.
    pub date: String,

    // Jurisdictional information string.
    pub info: String,

    /// Ballot chaining.
    pub ballot_chaining: BallotChaining,
}

impl VaryingParameters {
    /// Verifies the `VaryingParameters` meet some basic validity requirements.
    #[allow(clippy::nonminimal_bool)]
    pub fn validate(&self) -> Result<()> {
        // `n` must be greater than or equal to 1
        ensure!(
            1 <= self.n.get_one_based_u32(),
            "Varying parameters failed check: 1 <= n"
        );

        // `k` must be greater than or equal to 1
        ensure!(
            1 <= self.k.get_one_based_u32(),
            "Varying parameters failed check: 1 <= k"
        );

        // `k` must be less than or equal to `n`
        ensure!(self.k <= self.n, "Varying parameters failed check: k <= n");

        Ok(())
    }

    pub fn is_valid_guardian_i<T>(&self, i: T) -> bool
    where
        T: Into<u32>,
    {
        let i: u32 = i.into();
        (1..=self.n.get_one_based_u32()).contains(&i)
    }

    /// Iterates over the valid guardian numbers, 1 <= i <= [`VaryingParameters::n`].
    pub fn each_guardian_i(&self) -> impl Iterator<Item = GuardianIndex> {
        GuardianIndex::iter_range_inclusive(GuardianIndex::MIN, self.n)
    }
}
