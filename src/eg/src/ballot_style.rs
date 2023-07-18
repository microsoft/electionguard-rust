// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::collections::BTreeSet;

//? use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::election_manifest::ContestIndex;
use crate::index::GenericIndex;
use crate::vec1::Vec1;

/// A 1-based index of a `BallotStyle` in the order it is defined in the `ElectionManifest`.
pub type BallotStyleIndex = GenericIndex<BallotStyle>;

/// A ballot style.
/// TODO: write more?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BallotStyle {
    /// The label for this ballot style.
    pub label: String,

    /// The indices of the `Contest`s which appear on ballots of this style.
    pub contests: BTreeSet<ContestIndex>,
}

pub fn find_ballot_style(bs_str: &str, ballot_styles: &Vec1<BallotStyle>) -> Option<BallotStyle> {
    for i in 1..ballot_styles.len() + 1 {
        let i = BallotStyleIndex::from_one_based_index(i as u32).unwrap();
        let bs = ballot_styles.get(i).unwrap();
        if bs.label == *bs_str {
            return Some(bs.clone());
        }
    }

    None
}
