// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::ballot_style::{BallotStyle, BallotStyleIndex};
use crate::ciphertext::{Ciphertext, CiphertextIndex};
use crate::contest_data_fields::ContestDataFieldIndex;
use crate::errors::{EgError, EgResult};
use crate::index::Index;
use crate::selection_limit::{
    ContestSelectionLimit, EffectiveContestSelectionLimit, EffectiveOptionSelectionLimit,
    OptionSelectionLimit,
};
use crate::serializable::{SerializableCanonical, SerializablePretty};
use crate::vec1::{HasIndexType, HasIndexTypeMarker, Vec1};

/*
/// The configuration options for recording Overvotes and Undervotes for each Contest
/// on a Ballot.
pub enum UnderOverVoted {
    /// Under/Overvoted condition is not recorded.
    NotIncluded,

    /// The existance of an Under/Overvoted condition for this is recorded.
    FlagOnly,
    Quantitiy
}

/// Configuration options for recording specific conditions on an encrypted Ballot.
/// Enabling these configuration options generally increases the number of data fields for
/// each Contest, and thus the size of the encrypted Ballot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdditionalContestDataFields {
    // Overvote
    overvote: UnderOverVote,

    // Undervote
    undervote: UnderOverVote,

    // Record null vote
    null_vote: bool,

    // [Optional] Write in field
}
 */

/// The election manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectionManifest {
    /// A descriptive label for this election.
    label: String,

    /// All the [`Contest`]s in the election.
    contests: Vec1<Contest>,

    /// All the [`BallotStyle`]s of the election.
    ballot_styles: Vec1<BallotStyle>,
}

impl ElectionManifest {
    pub fn new(
        label: String,
        contests: Vec1<Contest>,
        ballot_styles: Vec1<BallotStyle>,
    ) -> EgResult<Self> {
        let mut self_ = Self {
            label,
            contests,
            ballot_styles,
        };
        self_.validate()?;
        Ok(self_)
    }

    /// Reads an [`ElectionManifest`] from a [`std::io::Read`] and validates it.
    /// It can be either the canonical or pretty JSON representation.
    pub fn from_stdioread_validated(stdioread: &mut dyn std::io::Read) -> EgResult<Self> {
        let mut self_: Self =
            serde_json::from_reader(stdioread).context("Reading ElectionManifest")?;
        self_.validate()?;
        Ok(self_)
    }

    /// Validates the [`ElectionManifest`] in some basic ways.
    /// You *must* call this after after deserialization for the manifest portion to be well-formed.
    /// Also informs Contests,
    /// ContestOptions, and BallotStyles of their indices if they don't know them.
    pub fn validate(&mut self) -> EgResult<()> {
        self.inform_contests_and_options_of_their_indices()?;
        self.inform_ballot_styles_of_their_index()?;

        // For each contest
        //    if the contest is present in zero ballot styles, issue a warning.
        //    if the stated selection limit is greater than the sum of the option selection limits, issue a warning.
        //    if the contest has a selection limit of 0, issue a warning
        //    For each option
        //       if the option has a selection limit of 0, issue a warning

        Ok(())
    }

    /// Returns the ElectionManifest's label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns access to the collection of [`Contests`].
    ///
    /// If you just want a specific contest:
    /// - If you know the ballot style, consider using `ballot_style.get_contest()`.
    /// - Otherwise, `election_manifest.get_contest_without_checking_ballot_style()`.
    pub fn contests(&self) -> &Vec1<Contest> {
        &self.contests
    }

    /// Returns access to the collection of [`BallotStyles`].
    /// If you just want a specific ballot style, consider using [`.get_ballot_style()`].
    pub fn ballot_styles(&self) -> &Vec1<BallotStyle> {
        &self.ballot_styles
    }

    /// Returns a ref to the [`BallotStyle`] at the specified index.
    pub fn get_ballot_style(&self, ballot_style_ix: BallotStyleIndex) -> EgResult<&BallotStyle> {
        self.ballot_styles
            .get(ballot_style_ix)
            .ok_or(EgError::BallotStyleNotInElectionManifest(ballot_style_ix))
    }

    /// Returns a ref to the [`Contest`] at the specified index.
    ///
    /// Note: If you know the ballot style, prefer to use the `ballot_style.get_contest()` instead.
    pub fn get_contest_without_checking_ballot_style(
        &self,
        contest_ix: ContestIndex,
    ) -> EgResult<&Contest> {
        self.contests
            .get(contest_ix)
            .ok_or(EgError::ContestNotInManifest(contest_ix))
    }

    // Inform the contests of their indices.
    // Also, inform the contest options of their indices.
    fn inform_contests_and_options_of_their_indices(&mut self) -> EgResult<()> {
        for (contest_ix, contest) in self.contests.enumerate_mut() {
            contest.inform_contest_of_its_index_and_its_options_of_theirs(contest_ix)?;
        }
        Ok(())
    }

    // Inform the ballot styles of their index.
    fn inform_ballot_styles_of_their_index(&mut self) -> EgResult<()> {
        for (actual_ballot_style_ix, ballot_style) in self.ballot_styles.enumerate_mut() {
            match ballot_style.opt_ballot_style_ix {
                Some(bs_ballot_style_ix) => {
                    if bs_ballot_style_ix != actual_ballot_style_ix {
                        return Err(EgError::BallotStyleIndexMismatch {
                            actual_ballot_style_ix,
                            bs_ballot_style_ix,
                        });
                    }
                }
                None => ballot_style.opt_ballot_style_ix = Some(actual_ballot_style_ix),
            }
        }
        Ok(())
    }
}

impl SerializableCanonical for ElectionManifest {}

impl SerializablePretty for ElectionManifest {}

/// A contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contest {
    /// The 1-based index of this [`Contest`] in the order it is defined in the
    /// [`ElectionManifest`].
    #[serde(skip)]
    pub opt_contest_ix: Option<ContestIndex>,

    /// The label for this `Contest`.
    pub label: String,

    /// The maximum number of selections ("votes") that may be distributed over all the selectable
    /// options of a contest.
    ///
    /// If not specified, the default is `1`.
    #[serde(default, skip_serializing_if = "ContestSelectionLimit::is_default")]
    pub selection_limit: ContestSelectionLimit,

    /// The contest options, e.g. "candidates".
    /// The order and quantity of contest options matches the contest's definition in the
    /// [`ElectionManifest`].
    pub contest_options: Vec1<ContestOption>,
}

impl Contest {
    /// Returns a ref to the [`ContestOption`] at index `ix`.
    pub fn get_contest_option(&self, ix: ContestDataFieldIndex) -> EgResult<&ContestOption> {
        self.contest_options
            .get(ix)
            .ok_or(EgError::ContestOptionIndexNotInContest(ix))
    }

    /// The effective selection limit for this contest.
    /// This is the smaller of this contest's selection limit and the sum of the options'
    /// selection limits.
    pub fn effective_contest_selection_limit(&self) -> EgResult<EffectiveContestSelectionLimit> {
        EffectiveContestSelectionLimit::figure(self)
    }

    /// The effective selection limits for every option of this contest.
    pub fn figure_options_effective_selection_limits(
        &self,
    ) -> EgResult<Vec1<EffectiveOptionSelectionLimit>> {
        let mut v = Vec::<EffectiveOptionSelectionLimit>::with_capacity(self.contest_options.len());
        for contest_option in self.contest_options.iter() {
            let esl = contest_option.effective_selection_limit(self)?;
            v.push(esl);
        }
        v.try_into()
    }

    // Informs the contest of its index.
    // Also, inform the contest options of their indices.
    fn inform_contest_of_its_index_and_its_options_of_theirs(
        &mut self,
        contest_ix: ContestIndex,
    ) -> EgResult<()> {
        match self.opt_contest_ix {
            Some(contests_contest_ix) => {
                if contests_contest_ix != contest_ix {
                    return Err(EgError::ContestIndexMismatch {
                        contest_ix,
                        contests_contest_ix,
                    });
                }
            }
            None => {
                self.opt_contest_ix = Some(contest_ix);
            }
        }

        for (contest_option_ix, contest_option) in self.contest_options.enumerate_mut() {
            // Verify or set the [`ContestOption`]'s understanding of its containing `contest_ix`.
            match self.opt_contest_ix {
                Some(co_contest_ix) => {
                    if co_contest_ix != contest_ix {
                        return Err(EgError::OptionContestIndexMismatch {
                            actual_contest_ix: contest_ix,
                            contest_option_ix,
                            co_contest_ix,
                        });
                    }
                }
                None => {
                    self.opt_contest_ix = Some(contest_ix);
                }
            }

            // Verify or set the [`ContestOption`]'s understanding of its own `contest_option_ix`.
            match contest_option.opt_contest_option_ix {
                Some(co_contest_option_ix) => {
                    if co_contest_option_ix != contest_option_ix {
                        return Err(EgError::ContestOptionIndexMismatch {
                            contest_ix,
                            actual_contest_option_ix: contest_option_ix,
                            co_contest_option_ix,
                        });
                    }
                }
                None => {
                    contest_option.opt_contest_option_ix = Some(contest_option_ix);
                }
            }
        }
        Ok(())
    }
}

impl HasIndexTypeMarker for Contest {}

/// A 1-based index of a [`Contest`] in the order it is defined in the [`ElectionManifest`].
pub type ContestIndex = Index<Contest>;

/// An option in a contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestOption {
    /// The 1-based index of the [`Contest`] to which this contest option belongs.
    #[serde(skip)]
    pub opt_contest_ix: Option<ContestIndex>,

    /// The 1-based index of this [`ContestOption`] within its [`Contest`].
    #[serde(skip)]
    pub opt_contest_option_ix: Option<ContestDataFieldIndex>,

    /// The label for this [`ContestOption`].
    pub label: String,

    /// The maximum number of selections ("votes") that a voter may apply to this contest option.
    ///
    /// If not specified, the default is `1`.
    #[serde(default, skip_serializing_if = "OptionSelectionLimit::is_default")]
    pub selection_limit: OptionSelectionLimit,
}

impl ContestOption {
    /// The effective selection limit for this contest option.
    /// This is the smaller of this options's selection limit and the contest's
    /// selection limit.
    pub fn effective_selection_limit(
        &self,
        containing_contest: &Contest,
    ) -> EgResult<EffectiveOptionSelectionLimit> {
        // If we happen to know the contest index of this option and the contest index of the containing
        // contest passed-in, verify they are the same.
        if let (Some(contestoption_contest_ix), Some(containing_contest_ix)) =
            (self.opt_contest_ix, containing_contest.opt_contest_ix)
        {
            if contestoption_contest_ix != containing_contest_ix {
                return Err(match self.opt_contest_option_ix {
                    Some(contest_option_ix) => EgError::ContestOptionActuallyInDifferentContest {
                        contest_option_ix,
                        containing_contest_ix,
                        contestoption_contest_ix,
                    },
                    None => EgError::ContestOptionActuallyInDifferentContest2 {
                        containing_contest_ix,
                        contestoption_contest_ix,
                    },
                });
            }
        }

        EffectiveOptionSelectionLimit::figure(containing_contest, self)
    }
}

/// A [`Vec1`] of [`ContestOption`] is indexed with the same type as [`Ciphertext`]
/// Same as [`ContestOptionFieldPlaintext`], [`ContestDataFieldPlaintext`], and possibly others.
impl HasIndexType for ContestOption {
    type IndexType = Ciphertext;
}

/// A 1-based index of a [`ContestOption`] in the order it is defined within its
/// [`Contest`], in the order it is defined in the [`ElectionManifest`].
///
/// Same type as [`CiphertextIndex`], [`ContestOptionFieldPlaintextIndex`], [`ContestDataFieldPlaintextIndex`], etc.
pub type ContestOptionIndex = CiphertextIndex;

// Unit tests for the election manifest.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use std::io::Cursor;

    use super::*;
    use crate::example_election_manifest::example_election_manifest;

    #[test]
    fn test_election_manifest() -> EgResult<()> {
        let election_manifest = example_election_manifest();

        // Pretty
        {
            let json_pretty = {
                let mut buf = Cursor::new(vec![0u8; 0]);
                election_manifest.to_stdiowrite_pretty(&mut buf)?;
                buf.into_inner()
            };
            assert!(json_pretty.len() > 6);
            assert_eq!(*json_pretty.last().unwrap(), b'\n');

            let election_manifest_from_json_pretty =
                ElectionManifest::from_stdioread_validated(&mut Cursor::new(json_pretty.clone()))?;

            let json_pretty_2 = {
                let mut buf = Cursor::new(vec![0u8; 0]);
                election_manifest_from_json_pretty.to_stdiowrite_pretty(&mut buf)?;
                buf.into_inner()
            };

            assert_eq!(json_pretty, json_pretty_2);
            assert_eq!(election_manifest, election_manifest_from_json_pretty);
        }

        // Canonical
        {
            let canonical_bytes = election_manifest.to_canonical_bytes()?;
            assert!(canonical_bytes.len() > 5);
            assert_ne!(canonical_bytes[canonical_bytes.len() - 1], b'\n');
            assert_ne!(canonical_bytes[canonical_bytes.len() - 1], 0x00);

            let election_manifest_from_canonical_bytes =
                ElectionManifest::from_stdioread_validated(&mut Cursor::new(canonical_bytes))?;

            assert_eq!(election_manifest, election_manifest_from_canonical_bytes);
        }

        Ok(())
    }
}
