// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::election_manifest::{Contest, ContestIndex};
use crate::errors::{EgError, EgResult};
use crate::index::Index;
use crate::pre_voting_data::PreVotingData;
use crate::vec1::HasIndexTypeMarker;

/// A 1-based index of a `BallotStyle` in the order it is defined in the `ElectionManifest`.
pub type BallotStyleIndex = Index<BallotStyle>;

/// A ballot style.
/// TODO: write more?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BallotStyle {
    /// The 1-based index of this [`BallotStyle`] in the order it is defined in the  [`ElectionManifest`].
    #[serde(skip)]
    pub opt_ballot_style_ix: Option<BallotStyleIndex>,

    /// The label for this ballot style.
    pub label: String,

    /// The indices of the `Contest`s which appear on ballots of this style.
    pub contests: BTreeSet<ContestIndex>,
}

impl HasIndexTypeMarker for BallotStyle {}

impl BallotStyle {
    /// Returns access to the collection of [`ContestIndex`]s.
    pub fn contests(&self) -> &BTreeSet<ContestIndex> {
        &self.contests
    }

    /// Returns [`Ok`](crate::errors::EgResult::Ok) if the specified contest exists in this [`BallotStyle`].
    ///
    /// - `contest_ix` - index of the contest to check for.
    pub fn contains_contest(&self, contest_ix: ContestIndex) -> EgResult<()> {
        if !self.contests.contains(&contest_ix) {
            return Err(EgError::ContestNotInBallotStyle {
                contest_ix,
                ballot_style_label: self.label.clone(),
                opt_ballot_style_ix: self.opt_ballot_style_ix,
            });
        }
        Ok(())
    }

    /// Returns a ref to the [`Contest`] at the specified [`ContestIndex`], if it exists in this
    /// [`BallotStyle`].
    ///
    /// - `contest_ix` - index of the contest to retrieve.
    pub fn get_contest<'a>(
        &self,
        pre_voting_data: &'a PreVotingData,
        contest_ix: ContestIndex,
    ) -> EgResult<&'a Contest> {
        self.contains_contest(contest_ix)?;
        pre_voting_data
            .manifest
            .get_contest_without_checking_ballot_style(contest_ix)
    }
}
