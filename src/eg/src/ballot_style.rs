// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use tracing::{error, trace};
use util::{index::Index, vec1::HasIndexType};

use crate::{
    contest_data_fields_ciphertexts::ContestDataFieldsCiphertexts,
    election_manifest::{Contest, ContestIndex, ElectionManifest, ElectionManifestInfo},
    errors::{EgError, EgResult, ResourceProductionError},
    resource::{
        ElectionDataObjectId, ProductionBudget, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource::{ProduceResource, ProduceResourceExt},
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

crate::impl_Resource_for_simple_ElectionDataObjectId_info_type! { BallotStyleInfo, BallotStyle }

impl SerializableCanonical for BallotStyleInfo {}

async fn contest_and_ballot_style_quantities(
    produce_resource: &(dyn crate::resource::ProduceResource + Send + Sync + 'static),
) -> EgResult<Option<(ContestIndex, BallotStyleIndex)>> {
    let mut ridfmt = ResourceIdFormat {
        rid: ResourceId::from(ElectionDataObjectId::ElectionManifest),
        fmt: ResourceFormat::ValidElectionDataObject,
    };

    let result = produce_resource
        .produce_resource_budget_downcast_no_src::<ElectionManifest>(
            &ridfmt,
            Some(ProductionBudget::Zero),
        )
        .await;
    match result {
        Ok(election_manifest) => {
            let qty_contests = election_manifest.qty_contests()?;
            let qty_ballot_styles = election_manifest.qty_ballot_styles()?;
            return Ok(Some((qty_contests, qty_ballot_styles)));
        }
        Err(e @ ResourceProductionError::ProductionBudgetInsufficient { .. }) => {
            // This is not an error
            trace!(
                "ballot style contest_and_ballot_style_quantities() didn't find the election manifest in the cache: {e}"
            );
        }
        Err(dep_err) => {
            let e: ResourceProductionError = ResourceProductionError::DependencyProductionError {
                ridfmt_request: ridfmt.clone(),
                dep_err: Box::new(dep_err),
            };
            error!("{e:?}");
            Err(e)?
        }
    }

    ridfmt.fmt = ResourceFormat::ConcreteType;
    let result = produce_resource
        .produce_resource_budget_downcast_no_src::<ElectionManifestInfo>(
            &ridfmt,
            Some(ProductionBudget::Zero),
        )
        .await;
    match result {
        Ok(election_manifest_into) => {
            let qty_contests = election_manifest_into.qty_contests()?;
            let qty_ballot_styles = election_manifest_into.qty_ballot_styles()?;
            return Ok(Some((qty_contests, qty_ballot_styles)));
        }
        Err(e @ ResourceProductionError::ProductionBudgetInsufficient { .. }) => {
            // This is not an error
            trace!(
                "ballot style contest_and_ballot_style_quantities() didn't find the ElectionManifestInfo in the cache: {e}"
            );
        }
        Err(dep_err) => {
            let e = ResourceProductionError::DependencyProductionError {
                ridfmt_request: ridfmt,
                dep_err: Box::new(dep_err),
            };
            error!("{e:?}");
            Err(e)?
        }
    }

    Ok(None)
}

crate::impl_validatable_validated! {
    src: BallotStyleInfo, produce_resource => EgResult<BallotStyle> {
        let BallotStyleInfo {
            opt_ballot_style_ix,
            label,
            contests,
        } = src;

        //----- Validate `label`.

        //? TODO can we impose any hard requirements on the label?

        if let Some((qty_contests, qty_ballot_styles)) = contest_and_ballot_style_quantities(produce_resource).await? {

            //----- Validate `opt_ballot_style_ix`.

            // If we have a ballot style index
            if let Some(ballot_style_ix) = opt_ballot_style_ix {
                // Verify that the ballot style index is in the election_manifest.
                if qty_ballot_styles < ballot_style_ix {
                    return Err(EgError::BallotStyleNotInElectionManifest(ballot_style_ix));
                }
            }

            //----- Validate `contests`.

            // Verify that every contest is present in the election_manifest.
            for &contest_ix in &contests {
                if qty_contests < contest_ix {
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

    /// Verify a set of [`ContestDataFieldsCiphertexts`]s.
    ///
    /// Typically these would be from one [`Ballot`], but really what they have in
    /// common is their [`BallotStyle`].
    ///
    /// It verifies:
    ///
    /// - That a [`ContestDataFieldsCiphertexts`] is supplied for every contest on the `BallotStyle`,
    /// - that every `ContestIndex` belongs to the `BallotStyle`, and that
    /// - all of the `ContestDataFieldsCiphertexts` proofs are correct.
    ///
    /// Supplying the `opt_ballot_style_ix` allows additional checks.
    ///
    pub async fn validate_contests_data_fields_ciphertexts(
        &self,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        contests_data_fields_ciphertexts: &BTreeMap<ContestIndex, ContestDataFieldsCiphertexts>,
        opt_ballot_style_ix: Option<BallotStyleIndex>,
    ) -> EgResult<()> {
        let election_manifest = produce_resource.election_manifest().await?;
        let election_manifest = election_manifest.as_ref();

        // Validates that the `BallotStyle` knows its `BallotStyleIndex`.
        // See `BallotStyle::get_validated_ballot_style_ix()` for details.
        let ballot_style_ix =
            self.get_validated_ballot_style_ix(opt_ballot_style_ix, Some(election_manifest))?;

        // Verify that every contest in the BallotStyle
        // - is present in this ballot's data fields ciphertexts.
        for &contest_ix in self.contests() {
            if !contests_data_fields_ciphertexts.contains_key(&contest_ix) {
                return Err(EgError::BallotMissingDataFieldsForContestInBallotStyle {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        // Verify that every contest for which data fields ciphertexts are supplied
        // is present in the ballot style.
        for &contest_ix in contests_data_fields_ciphertexts.keys() {
            if !self.contests().contains(&contest_ix) {
                return Err(EgError::BallotClaimsContestNonExistentInBallotStyle {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        // Verify the proofs for all data fields for every contest for which
        // data fields ciphertexts are supplied.
        let mut verified_contests = BTreeSet::<ContestIndex>::new();
        for (&contest_ix, contest_fields_ciphertexts) in contests_data_fields_ciphertexts.iter() {
            contest_fields_ciphertexts
                .verify_proofs_for_all_data_fields_in_contest(produce_resource)
                .await?;

            verified_contests.insert(contest_ix);
        }

        // Verify that we verified all contests in the ballot style.
        for &contest_ix in self.contests() {
            if !verified_contests.contains(&contest_ix) {
                return Err(EgError::BallotContestNotVerified {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        // Verify that all contests we verified are in the ballot style.
        for &contest_ix in verified_contests.iter() {
            if !self.contests().contains(&contest_ix) {
                return Err(EgError::BallotContestVerifiedNotInBallotStyle {
                    ballot_style_ix,
                    contest_ix,
                });
            }
        }

        Ok(())
    }
}

crate::impl_knows_friendly_type_name! { BallotStyle }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { BallotStyle, BallotStyle }

impl SerializableCanonical for BallotStyle {}
