// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use util::{index::Index, vec1::HasIndexType};

use crate::{
    eg::Eg,
    election_manifest::{Contest, ContestIndex, ElectionManifest},
    errors::{EgError, EgResult},
    resource::ElectionDataObjectId,
    serializable::SerializableCanonical,
};

/// A ballot style.
/// TODO: write more?
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
pub struct BallotStyleInfo {
    /// The 1-based index of this [`BallotStyle`] in the order it is defined in the  [`ElectionManifest`].
    #[serde(skip)]
    pub opt_ballot_style_ix: Option<BallotStyleIndex>,

    /// The label for this ballot style.
    pub label: String,

    /// The indices of the `Contest`s which appear on ballots of this style.
    pub contests: BTreeSet<ContestIndex>,
}

impl HasIndexType for BallotStyleInfo {
    type IndexTypeParam = BallotStyle;
}

/// A 1-based index of a `BallotStyle` in the order it is defined in the `ElectionManifest`.
pub type BallotStyleIndex = Index<BallotStyle>;

crate::impl_knows_friendly_type_name! { BallotStyleInfo }

crate::impl_MayBeResource_for_non_Resource! { BallotStyleInfo }

crate::impl_validatable_validated! {
    src: BallotStyleInfo, eg => EgResult<BallotStyle> {
        let BallotStyleInfo {
            opt_ballot_style_ix,
            label,
            contests,
        } = src;

        //----- Validate `label`.

        //? TODO can we impose any hard requirements on the label?

        // If we have a election_manifest
        let election_manifest_ridfmt = ElectionDataObjectId::ElectionParameters.validated_type_ridfmt();
        if let Ok(rc_election_manifest) = eg.produce_resource_downcast_no_src::<ElectionManifest>(&election_manifest_ridfmt) {
            let election_manifest = rc_election_manifest.as_ref();

            //----- Validate `opt_ballot_style_ix`.

            // If we have a ballot style index
            if let Some(ballot_style_ix) = opt_ballot_style_ix {
                // Verify that the ballot style index is in the election_manifest.
                if !election_manifest.ballot_styles().contains_index(ballot_style_ix) {
                    return Err(EgError::BallotStyleNotInElectionManifest(ballot_style_ix));
                }
            }

            //----- Validate `contests`.

            // Verify that every contest is present in the election_manifest.
            for &contest_ix in &contests {
                if !election_manifest.contests().contains_index(contest_ix) {
                    // Use `ballot_style_ix` for reporting, if known.
                    return Err(opt_ballot_style_ix.map_or_else(
                        || EgError::ContestNotInManifest(contest_ix),
                        |ballot_style_ix| EgError::BallotStyleClaimsNonExistentContest { ballot_style_ix, contest_ix }
                    ));
                }
            }
        }

        //----- Construct the object from the validated data.

        Ok(Self {
            opt_ballot_style_ix,
            label,
            contests,
        })
    }
}

impl From<BallotStyle> for BallotStyleInfo {
    /// Convert from BallotStyle back to a BallotStyleInfo for re-validation.
    fn from(src: BallotStyle) -> Self {
        let BallotStyle {
            opt_ballot_style_ix,
            label,
            contests,
        } = src;

        BallotStyleInfo {
            opt_ballot_style_ix,
            label,
            contests,
        }
    }
}

/// A ballot style.
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BallotStyle {
    #[serde(skip)]
    opt_ballot_style_ix: Option<BallotStyleIndex>,
    label: String,
    contests: BTreeSet<ContestIndex>,
}

impl HasIndexType for BallotStyle {
    type IndexTypeParam = BallotStyle;
}

impl BallotStyle {
    /// Returns the [`BallotStyleIndex`] of this [`BallotStyle`].
    /// If the BallotStyle doesn't know its index, returns an error.
    pub fn get_ballot_style_ix(&self) -> EgResult<BallotStyleIndex> {
        self.opt_ballot_style_ix
            .ok_or(EgError::BallotStyleDoesntKnowItsIndexAndItWasNotClearFromContextEither)
    }

    /// Returns a mut ref to the [`opt_ballot_style_ix`] member, allowing
    /// to modify, remove, or replace it.
    pub fn mut_opt_ballot_style_ix(&mut self) -> &mut Option<BallotStyleIndex> {
        &mut self.opt_ballot_style_ix
    }

    /// Verifies that the [`BallotStyle`]:
    /// - knows its [`BallotStyleIndex`],
    /// - its `BallotStyleIndex` matches any caller-supplied index, if any, and
    /// - compares equal to the `BallotStyle` at that index in any supplied [`ElectionManifest`],
    ///
    /// If you just retrieved the `BallotStyle` from the `ElectionManifest`, provide the index
    /// from which it was retrieved via `opt_ballot_style_ix` but set `opt_election_manifest`
    /// to `None`. The additional work it prompts is not useful.
    ///
    pub fn get_validated_ballot_style_ix(
        &self,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
        opt_election_manifest: Option<&ElectionManifest>,
    ) -> EgResult<BallotStyleIndex> {
        // The BallotStyle must know its index
        let ballot_style_ix = self.get_ballot_style_ix().map_err(|e| {
            // We can improve the error message if the caller supplied a `BallotStyleIndex`.
            opt_ballot_style_ix.map_or(e, EgError::BallotStyleDoesntKnowItsIndex)
        })?;

        // The BallotStyle's belief about its index must match any caller-supplied index
        if let Some(supplied_bs_ix) = opt_ballot_style_ix {
            if supplied_bs_ix != ballot_style_ix {
                return Err(EgError::BallotStyleIndexMismatch {
                    actual_ballot_style_ix: supplied_bs_ix,
                    bs_ballot_style_ix: ballot_style_ix,
                });
            }
        };

        // If an `ElectionManifest` was supplied, there must be a `BallotStyle` at the
        // expected index, and it must compare equal to this `BallotStyle`.
        if let Some(election_manifest) = opt_election_manifest {
            // Note: Don't call `self.get_ballot_style()` here, because it calls us.
            let ballot_style_from_manifest = election_manifest
                .ballot_styles()
                .get(ballot_style_ix)
                .ok_or(EgError::BallotStyleNotInElectionManifest(ballot_style_ix))?;

            if *self != *ballot_style_from_manifest {
                return Err(EgError::BallotStyleDoesntMatchElectionManifest(
                    ballot_style_ix,
                ));
            }
        }

        Ok(ballot_style_ix)
    }

    /// The label of this [`BallotStyle`].
    pub fn label(&self) -> &String {
        &self.label
    }

    /// The collection of [`ContestIndex`]s in this [`BallotStyle`].
    pub fn contests(&self) -> &BTreeSet<ContestIndex> {
        &self.contests
    }

    /// Returns [`Ok`](crate::errors::EgResult::Ok) if the specified contest exists in this
    /// [`BallotStyle`].
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
    /// - `election_manifest` - The [`ElectionManifest`].
    /// - `contest_ix` - index of the contest to retrieve.
    pub fn get_contest<'a>(
        &self,
        election_manifest: &'a ElectionManifest,
        contest_ix: ContestIndex,
    ) -> EgResult<&'a Contest> {
        self.contains_contest(contest_ix)?;
        election_manifest.get_contest_without_checking_ballot_style(contest_ix)
    }
}

crate::impl_knows_friendly_type_name! { BallotStyle }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { BallotStyle, BallotStyle }

impl SerializableCanonical for BallotStyle {}
