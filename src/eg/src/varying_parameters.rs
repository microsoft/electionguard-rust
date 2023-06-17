// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

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
