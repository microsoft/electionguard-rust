// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::collections::BTreeSet;

//? use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::election_manifest::ContestIndex;
use crate::index::Index;

/// A 1-based index of a `BallotStyle` in the order it is defined in the `ElectionManifest`.
pub type BallotStyleIndex = Index<BallotStyle>;

/// A ballot style.
/// TODO: write more?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BallotStyle {
    /// The label for this ballot style.
    pub label: String,

    /// The indices of the `Contest`s which appear on ballots of this style.
    pub contests: BTreeSet<ContestIndex>,
}
