// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::num::NonZeroU16;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// The parameters for a specific election.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Iterates over the guardian numbers, 1 <= i <= n.
    /// This is useful because `NonZeroU16` doesn't (yet) implement
    /// the `Step` trait necessary for iteration.
    ///
    /// See rust issue 73121 "[ER] NonZeroX Step and better constructors"
    /// https://github.com/rust-lang/rust/issues/73121
    /// and libs-team issue 130 "Implement Step for NonZeroUxx"
    /// https://github.com/rust-lang/libs-team/issues/130
    pub fn each_guardian_i(&self) -> impl Iterator<Item = NonZeroU16> {
        (1..=self.n).map(|i| {
            // `unwrap()` is justified here because we iterate over `1..=n`
            #[allow(clippy::unwrap_used)]
            NonZeroU16::new(i).unwrap()
        })
    }
}
