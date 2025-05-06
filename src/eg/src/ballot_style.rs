// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use downcast_rs::{DowncastSync, impl_downcast};
use either::Either;
use serde::{Deserialize, Serialize};
use static_assertions::assert_obj_safe;
#[allow(unused_imports)]
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

//
use util::{
    index::Index,
    vec1::{HasIndexType, Vec1},
};

use crate::{
    contest::{Contest, ContestIndex},
    contest_data_fields_ciphertexts::ContestDataFieldsCiphertexts,
    election_manifest::{ElectionManifest, ElectionManifestInfo},
    errors::{EgError, EgResult, ResourceProductionError},
    label::{LabeledItem, validate_label},
    resource::{
        ElectionDataObjectId, ProductionBudget, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource::{ProduceResource, ProduceResourceExt},
    serializable::SerializableCanonical,
};

//=================================================================================================|

/// A 1-based index of a `BallotStyle` in the order it is defined in the `ElectionManifest`.
pub type BallotStyleIndex = Index<BallotStyle>;

impl HasIndexType for BallotStyleInfo {
    type IndexTypeParam = BallotStyle;
}

impl HasIndexType for BallotStyle {
    type IndexTypeParam = BallotStyle;
}

impl HasIndexType for dyn BallotStyleTrait {
    type IndexTypeParam = BallotStyle;
}

//-------------------------------------------------------------------------------------------------|

#[allow(non_camel_case_types)]
pub type BoxBallotStyleInfo_or_BoxBallotStyle = Either<Box<BallotStyleInfo>, Box<BallotStyle>>;

#[allow(non_camel_case_types)]
pub type ArcBallotStyleInfo_or_ArcBallotStyle = Either<Arc<BallotStyleInfo>, Arc<BallotStyle>>;

//-------------------------------------------------------------------------------------------------|

//#[async_trait::async_trait(?Send)]
/// Element access common to [`EdoTemplateSimpleInfo`] and [`EdoTemplateSimple`].
pub trait BallotStyleTrait: DowncastSync {
    /// The 1-based index of this [`BallotStyle`] in the order it is defined in the
    /// [`ElectionManifest`], if known.
    fn opt_ballot_style_ix(&self) -> Option<BallotStyleIndex>;

    /// The Label of this [`BallotStyle`].
    fn label(&self) -> &str;

    /*
    /// The collection of [`ContestIndex`]s in this [`BallotStyle`].
    fn contests(&self) -> &BTreeSet<ContestIndex>;
    // */

    /// Returns the [`BallotStyleIndex`] of this [`BallotStyle`].
    /// If the BallotStyle doesn't know its index, returns an error.
    fn get_ballot_style_ix(&self) -> EgResult<BallotStyleIndex> {
        self.opt_ballot_style_ix()
            .ok_or(EgError::BallotStyleDoesntKnowItsIndexAndItWasNotClearFromContextEither)
    }

    /// Sets the [`BallotStyleIndex`].
    ///
    /// Returns [`EgError`] if the `BallotStyle`(`Info`) is already set to a different value.
    fn provide_ballot_style_ix(&mut self, ballot_style_ix: BallotStyleIndex) -> EgResult<()>;

    /// Checks that the [`BallotStyle`]:
    ///
    /// - knows its [`BallotStyleIndex`], and
    /// - its `BallotStyleIndex` matches the caller-supplied value.
    fn validate_ballot_style_ix(&self, ballot_style_ix: BallotStyleIndex) -> EgResult<()> {
        let Some(current_ballot_style_ix) = self.opt_ballot_style_ix() else {
            let e = EgError::BallotStyleDoesntKnowItsIndex(ballot_style_ix);
            trace!("{e}");
            return Err(e);
        };

        if current_ballot_style_ix != ballot_style_ix {
            let e = EgError::BallotStyleIndexMismatch {
                actual_ballot_style_ix: ballot_style_ix,
                bs_ballot_style_ix: current_ballot_style_ix,
            };
            trace!("{e}");
            return Err(e);
        }

        Ok(())
    }
}

// Helper for implementing  BallotStyleTrait::provide_ballot_style_ix().
fn provide_ballot_style_ix_common_impl_(
    current_opt_ballot_style_ix: &mut Option<BallotStyleIndex>,
    ballot_style_ix: BallotStyleIndex,
) -> EgResult<()> {
    match current_opt_ballot_style_ix {
        Some(current_ballot_style_ix) => {
            if *current_ballot_style_ix != ballot_style_ix {
                let e = EgError::BallotStyleIndexMismatch {
                    actual_ballot_style_ix: ballot_style_ix,
                    bs_ballot_style_ix: *current_ballot_style_ix,
                };
                trace!("{e}");
                return Err(e);
            }
        }
        None => *current_opt_ballot_style_ix = Some(ballot_style_ix),
    }
    Ok(())
}

assert_obj_safe!(BallotStyleTrait);

impl_downcast!(sync BallotStyleTrait);

//-------------------------------------------------------------------------------------------------|

/// If the `ballot_style_ix` is known and *not* within the range of
/// `1..=cnt_ballot_styles_in_election_manifest`, returns
/// [`EgError::BallotStyleNotInElectionManifest`].
pub fn validate_opt_ballot_style_ix(
    opt_ballot_style_ix: Option<BallotStyleIndex>,
    cnt_ballot_styles_in_election_manifest: BallotStyleIndex,
) -> EgResult<()> {
    // S3.1.3.f EGRI rejects any Election Manifest having a Ballot Style with a Contest Index
    // list containing a Contest Index that does not refer to a contest in the
    // Election Manifest.
    if let Some(ballot_style_ix) = opt_ballot_style_ix {
        if cnt_ballot_styles_in_election_manifest < ballot_style_ix {
            return Err(EgError::BallotStyleNotInElectionManifest {
                ballot_style_ix,
                election_manifest_cnt_ballot_styles: cnt_ballot_styles_in_election_manifest.into(),
            });
        }
    }
    Ok(())
}

//-------------------------------------------------------------------------------------------------|

/// A not-yet-validated BallotStyle.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
pub struct BallotStyleInfo {
    /// The 1-based index of this [`BallotStyle`] in the order it is defined in the  [`ElectionManifest`].
    #[serde(skip)]
    pub opt_ballot_style_ix: Option<BallotStyleIndex>,

    /// The label for this ballot style.
    pub label: String,

    /// The indices of the `Contest`s which appear on ballots of this style.
    pub contests: Vec<ContestIndex>,
}

impl BallotStyleTrait for BallotStyleInfo {
    fn opt_ballot_style_ix(&self) -> Option<BallotStyleIndex> {
        self.opt_ballot_style_ix
    }

    fn label(&self) -> &str {
        self.label.as_str()
    }

    /*
    fn contests(&self) -> &BTreeSet<ContestIndex> {
        &self.contests
    }
    // */

    fn provide_ballot_style_ix(&mut self, ballot_style_ix: BallotStyleIndex) -> EgResult<()> {
        provide_ballot_style_ix_common_impl_(&mut self.opt_ballot_style_ix, ballot_style_ix)
    }
}

crate::impl_knows_friendly_type_name! { BallotStyleInfo }

crate::impl_Resource_for_simple_ElectionDataObjectId_info_type! { BallotStyleInfo, BallotStyle }

impl SerializableCanonical for BallotStyleInfo {}

/*
async fn contest_and_ballot_style_quantities(
    produce_resource: &(dyn crate::resource::ProduceResource + Send + Sync + 'static),
) -> EgResult<(Option<ContestIndex>, Option<BallotStyleIndex>)> {
    let mut ridfmt = ResourceIdFormat {
        rid: ResourceId::from(ElectionDataObjectId::ElectionManifest),
        fmt: ResourceFormat::ValidElectionDataObject,
    };

    // First, try to get a validated ElectionManifest in the cache.
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
            return Ok((Some(qty_contests), Some(qty_ballot_styles)));
        }
        Err(e @ ResourceProductionError::ProductionBudgetInsufficient { .. }) => {
            // This is not an error
            trace!(
                "Ballot_style::contest_and_ballot_style_quantities() didn't find a validated `ElectionManifest` in the cache: {e}"
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

    // Then try to get a not-yet-validated ElectionManifestInfo from the cache.
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
            return Ok((Some(qty_contests), Some(qty_ballot_styles)));
        }
        Err(e @ ResourceProductionError::ProductionBudgetInsufficient { .. }) => {
            // This is not an error
            trace!(
                "Ballot_style::contest_and_ballot_style_quantities() didn't find a not-yet-validated `ElectionManifestInfo` in the cache: {e}"
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

    Ok((None, None))
}
// */

crate::impl_validatable_validated! {
    src: BallotStyleInfo, produce_resource => EgResult<BallotStyle> {
        let BallotStyleInfo {
            opt_ballot_style_ix,
            label,
            contests: v_contests,
        } = src;

        /* //? TODO
        // See if we can get info on qty_contests and qty_ballot_styles from the ElectionManifest(Info).
        let (opt_qty_contests, opt_qty_ballot_styles) = contest_and_ballot_style_quantities(produce_resource).await?;
        // */

        //----- Validate `label`.

        // EGDS 2.1.0 S3.1.3.b EGRI accepts BallotStyle labels composed of printable characters and (internal, non-contiguous) 0x20 space characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels that contain line break characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels that have leading or trailing whitespace
        // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels that contain contiguous sequences of whitespace other than a single 0x20 space
        // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels that contain special characters (Unicode Category Cc, Cf, Zs, Zl, Zp, or Cs)
        // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels having no printable characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels that decode to a Unicode malformed surrogate pair (Unicode Category Cs). See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603)
        validate_label(label.as_str(), LabeledItem::BallotStyle(opt_ballot_style_ix))?;

        //----- Validate `contests`, without reference to ElectionManifest(Info).

        // Can't validate the `ContestIndex`s because we don't yet know the number of Contests in the ElectionManifest.
        // We will perform that check as part of the ElectionManifest(Info) validation.

        //? TODO S3.1.3.f EGRI rejects any ElectionManifest listing the same Contest Index more than once within the same Ballot Style.
        // EGDS 2.1.0 S3.1.3.f EGRI rejects any ElectionManifest listing the same Contest Index more than once within the same Ballot Style.

        let mut contests: BTreeSet<ContestIndex> = BTreeSet::new();
        for contest_ix in v_contests {
            let newly_inserted = contests.insert(contest_ix);
            if !newly_inserted {
                let e = match opt_ballot_style_ix {
                    Some(ballot_style_ix) => EgError:: BallotStyleByIndexAndLabelDuplicateContest {
                        ballot_style_ix,
                        ballot_style_label: label,
                        contest_ix,
                    },
                    None => EgError::BallotStyleByLabelDuplicateContest {
                        ballot_style_label: label,
                        contest_ix,
                    },
                };
                trace!("{e}");
                return Err(e);
            }
        }

        //----- Validate `opt_ballot_style_ix`.

        // Can't validate the `BallotStyleIndex`s because we don't yet know the number of BallotStyles in the ElectionManifest.
        // We will perform that check as part of the ElectionManifest(Info) validation.

        /* //? TODO
        if let Some(qty_ballot_styles) = opt_qty_ballot_styles {
            validate_opt_ballot_style_ix(opt_ballot_style_ix, qty_ballot_styles)?;
        }
        // */

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
            contests: contests.into_iter().collect(),
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

impl BallotStyleTrait for BallotStyle {
    fn opt_ballot_style_ix(&self) -> Option<BallotStyleIndex> {
        self.opt_ballot_style_ix
    }

    fn label(&self) -> &str {
        &self.label
    }

    /*
    fn contests(&self) -> &BTreeSet<ContestIndex> {
        &self.contests
    }
    // */

    fn provide_ballot_style_ix(&mut self, ballot_style_ix: BallotStyleIndex) -> EgResult<()> {
        provide_ballot_style_ix_common_impl_(&mut self.opt_ballot_style_ix, ballot_style_ix)
    }
}

impl BallotStyle {
    /// The collection of [`ContestIndex`]s in this [`BallotStyle`].
    pub fn contests(&self) -> &BTreeSet<ContestIndex> {
        &self.contests
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
                .ok_or(EgError::BallotStyleNotInElectionManifest {
                    ballot_style_ix,
                    election_manifest_cnt_ballot_styles: election_manifest.ballot_styles().len(),
                })?;

            if *self != **ballot_style_from_manifest {
                return Err(EgError::BallotStyleDoesntMatchElectionManifest(
                    ballot_style_ix,
                ));
            }
        }

        Ok(ballot_style_ix)
    }

    /// Returns [`Ok`](EgResult::Ok) if the specified [`Contest`] exists in this
    /// [`BallotStyle`].
    ///
    /// - `contest_ix` - index of the contest to check for.
    pub fn contains_contest(&self, contest_ix: ContestIndex) -> EgResult<()> {
        if !self.contests().contains(&contest_ix) {
            return Err(EgError::ContestNotInBallotStyle {
                contest_ix,
                ballot_style_label: self.label().to_string(),
                opt_ballot_style_ix: self.opt_ballot_style_ix(),
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

    /// Checks that all [`ContestIndex`]s listed in this [`BallotStyle`]
    /// are present in the supplied collection of contests from the [`ElectionManifest`].
    pub fn validate_contest_indexes(
        &self,
        election_manifest_contests: &Vec1<Contest>,
    ) -> EgResult<()> {
        for &contest_ix in self.contests() {
            if !election_manifest_contests.contains_index(contest_ix) {
                let e = EgError::BallotStyleContestNotInElectionManifest {
                    opt_ballot_style_ix: self.opt_ballot_style_ix(),
                    ballot_style_label: self.label().to_string(),
                    contest_ix,
                };
                trace!("{e}");
                return Err(e);
            }
        }
        Ok(())
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

//-------------------------------------------------------------------------------------------------|

/// For a [`&mut Vec1`] of [`BallotStyleInfo`s], inform each of its [`BallotStyleIndex`].
///
/// Returns [`EgError`] if any already believes it has an incorrect BallotStyleIndex.
pub fn inform_bx_ballot_style_infos_of_their_indices(
    v1_bxbsi: &mut Vec1<Box<BallotStyleInfo>>,
) -> EgResult<()> {
    for (ballot_style_ix, bxbsi) in v1_bxbsi.enumerate_mut() {
        bxbsi.provide_ballot_style_ix(ballot_style_ix)?;
    }
    Ok(())
}

/// For a [`Vec1`] of [`&mut dyn BallotStyleTrait`s](BallotStyleTrait), inform each of its
/// [`BallotStyleIndex`].
///
/// Returns [`EgError`] if any BallotStyle already believes it has a BallotStyleIndex and it is wrong.
pub fn inform_ballot_styles_of_their_indices(
    v1_bxbsi_or_bxbs: &mut Vec1<Either<Box<BallotStyleInfo>, Box<BallotStyle>>>,
) -> EgResult<()> {
    for (ballot_style_ix, bxbsi_or_bxbs) in v1_bxbsi_or_bxbs.enumerate_mut() {
        either::for_both!(bxbsi_or_bxbs, bx => bx.provide_ballot_style_ix(ballot_style_ix))?;
    }
    Ok(())
}

/// Converts a [`Vec1<BoxBallotStyleInfo_or_BoxBallotStyle>`]
/// to a [`Vec1<ArcBallotStyleInfo_or_ArcBallotStyle>`]. Also ensures that all the resulting
/// [`BallotStyle`]/[`BallotStyleInfo`]s have correct knowledge of their indices.
pub fn v1_either_bxbsi_or_bxbs_to_v1_either_arcbsi_or_arcbs(
    mut v1_bxbsi_or_bxbs: Vec1<BoxBallotStyleInfo_or_BoxBallotStyle>,
) -> EgResult<Vec1<ArcBallotStyleInfo_or_ArcBallotStyle>> {
    inform_ballot_styles_of_their_indices(&mut v1_bxbsi_or_bxbs)?;

    let v1_arcbsi_or_arcbs: Vec1<ArcBallotStyleInfo_or_ArcBallotStyle> =
        v1_bxbsi_or_bxbs.map_into(|bxbsi_or_bxbs| {
            //either::for_both!(either_bxbsi_or_bxbs, bxbsi_or_bxbs => bxbsi_or_bxbs.into()
            match bxbsi_or_bxbs {
                Either::Left(bxbsi) => Either::Left(bxbsi.into()),
                Either::Right(bxbs) => Either::Right(bxbs.into()),
            }
        });

    Ok(v1_arcbsi_or_arcbs)
}

//=================================================================================================|

// Unit tests for the BallotStyle.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod t {
    use insta::{assert_ron_snapshot, assert_snapshot};
    use serde_json::{Value as JsonValue, json};

    use super::*;
    #[allow(unused_imports)] //? TODO: Remove temp development code
    use crate::{
        eg::Eg,
        election_manifest::{ElectionManifestInfo, t::common_test_election_manifest_jv},
        loadable::{LoadableFromStdIoReadValidatable, LoadableFromStdIoReadValidated},
        serializable::{SerializableCanonical, SerializablePretty},
        validatable::{Validatable, Validated},
    };

    async fn test_ballotstyle_label(ballot_style_label: &str) -> EgResult<()> {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(format!(
            "eg::ballot_style::t::test_ballotstyle_label: {ballot_style_label:?}"
        ));
        let eg = eg.as_ref();

        let mut em_jv = common_test_election_manifest_jv(0);
        em_jv["ballot_styles"] = json!([
            { "label": ballot_style_label, "contests": [ ] }
        ]);

        let em_js = serde_json::to_string_pretty(&em_jv).unwrap();

        let em_info = ElectionManifestInfo::from_json_str_validatable(em_js.as_str()).unwrap();

        ElectionManifest::try_validate_from(em_info, eg).map(|_| ())
    }

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            // EGDS 2.1.0 S3.1.3.b EGRI accepts BallotStyle labels composed of printable characters and (internal, non-contiguous) 0x20 space characters

            assert_ron_snapshot!(test_ballotstyle_label(
                    "bs1"
                ).await,
                @"Ok(())");

            assert_ron_snapshot!(test_ballotstyle_label(
                    "Smoothstone County local ballot"
                ).await,
                @"Ok(())");

            assert_ron_snapshot!(test_ballotstyle_label(
                    "Ætherwïng Party Primary for Silvërspîre County Residents"
                ).await,
                @"Ok(())");
        });
    }

    #[test_log::test]
    fn t2() {
        async_global_executor::block_on(async {
            // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels that contain line break characters
            assert_ron_snapshot!(test_ballotstyle_label(
                    "BallotStyle\nlabel\nthat contains line break characters"
                ).await,
                @r#"
            Err(LabelError(NotAllowedChar(CharNotAllowedInText(
              labeled_item: BallotStyle(Some(1)),
              char_ix1: 12,
              byte_offset: 11,
              unicode_property: Control,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels that have leading or trailing whitespace
            assert_ron_snapshot!(test_ballotstyle_label(
                    " BallotStyle label that has leading whitespace"
                ).await,
                @r#"
            Err(LabelError(LeadingOrTrailingWhitespace((Leading, CharNotAllowedInText(
              labeled_item: BallotStyle(Some(1)),
              char_ix1: 1,
              byte_offset: 0,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            )))))"#);

            assert_ron_snapshot!(test_ballotstyle_label(
                    "BallotStyle label that has trailing whitespace "
                ).await,
                @r#"
            Err(LabelError(LeadingOrTrailingWhitespace((Trailing, CharNotAllowedInText(
              labeled_item: BallotStyle(Some(1)),
              char_ix1: 47,
              byte_offset: 46,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            )))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels that contain contiguous sequences of whitespace other than a single 0x20 space
            assert_ron_snapshot!(test_ballotstyle_label(
                    "BallotStyle  label that contains contiguous sequences of whitespace"
                ).await,
                @r#"
            Err(LabelError(ContiguousWhitespace(CharNotAllowedInText(
              labeled_item: BallotStyle(Some(1)),
              char_ix1: 13,
              byte_offset: 12,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels that contain special characters (Unicode Category Cc, Cf, Zs, Zl, Zp, or Cs)
            // 0x002028 - LINE SEPARATOR - 'Zl'
            assert_ron_snapshot!(test_ballotstyle_label(
                    "BallotStyle\u{002028}label that contains a special character"
                ).await,
                @r#"
            Err(LabelError(NotAllowedChar(CharNotAllowedInText(
              labeled_item: BallotStyle(Some(1)),
              char_ix1: 12,
              byte_offset: 11,
              unicode_property: LineSeparator,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels having no printable characters
            assert_ron_snapshot!(test_ballotstyle_label(
                    ""
                ).await,
                @"Err(LabelError(NoPossiblyPrintableCharacters(BallotStyle(Some(1)))))");

            assert_ron_snapshot!(test_ballotstyle_label(
                    "\u{00200C}"
                ).await,
                @"Err(LabelError(NoPossiblyPrintableCharacters(BallotStyle(Some(1)))))");

            //? TODO EGDS 2.1.0 S3.1.3.b EGRI rejects BallotStyle labels that decode to a Unicode malformed surrogate pair (Unicode Category Cs). See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603)
            //? TODO
        });
    }

    /// Common to tests t3, t4, and t5.
    async fn common_t345(seed_str: &str, bs1_contests: Vec<u32>) -> (JsonValue, EgResult<()>) {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(seed_str);
        let eg = eg.as_ref();

        let mut em_jv = common_test_election_manifest_jv(3);
        em_jv["ballot_styles"] = json!([
            { "label": "Ballot Style 1", "contests": bs1_contests }
        ]);

        let em_js = serde_json::to_string_pretty(&em_jv).unwrap();

        let em_info = ElectionManifestInfo::from_json_str_validatable(em_js.as_str()).unwrap();

        let result = ElectionManifest::try_validate_from(em_info, eg).map(|_| ());

        (em_jv, result)
    }

    #[test_log::test]
    fn t3() {
        async_global_executor::block_on(async {
            // Tests success case for common_t345

            let (em_json, result) = common_t345("eg::ballot_style::t::t3", vec![1, 2, 3]) // expect Ok
                .await;

            assert_snapshot!(em_json["ballot_styles"][0]["contests"], @"[1,2,3]");

            assert_ron_snapshot!(result, @"Ok(())");
        })
    }

    #[test_log::test]
    fn t4() {
        async_global_executor::block_on(async {
            // EGDS 2.1.0 S3.1.3.f EGRI rejects any Election Manifest having a Ballot Style with a Contest Index list containing a Contest Index that does not refer to a contest in the Election Manifest.

            let (em_json, result) = common_t345("eg::ballot_style::t::t4", vec![1, 2, 2]) // expect Err
                .await;

            assert_snapshot!(em_json["ballot_styles"][0]["contests"], @"[1,2,2]");

            assert_ron_snapshot!(result, @r#"
                Err(BallotStyleByIndexAndLabelDuplicateContest(
                  ballot_style_ix: 1,
                  ballot_style_label: "Ballot Style 1",
                  contest_ix: 2,
                ))
            "#);
        })
    }

    #[test_log::test]
    fn t5() {
        async_global_executor::block_on(async {
            // EGDS 2.1.0 S3.1.3.f EGRI rejects any Election Manifest having a Ballot Style with a Contest Index list containing a Contest Index that does not refer to a contest in the Election Manifest.

            let (em_json, result) = common_t345("eg::ballot_style::t::t5", vec![1, 2, 3, 999]) // expect Err
                .await;

            assert_snapshot!(em_json["ballot_styles"][0]["contests"], @"[1,2,3,999]");

            assert_ron_snapshot!(result, @r#"
            Err(BallotStyleContestNotInElectionManifest(
              opt_ballot_style_ix: Some(1),
              ballot_style_label: "Ballot Style 1",
              contest_ix: 999,
            ))
            "#);
        })
    }
}
