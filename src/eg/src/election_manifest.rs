// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::{borrow::Cow, sync::Arc};

use either::Either;
use serde::{Deserialize, Serialize};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

use util::{
    index::Index,
    text::truncate_text,
    vec1::{HasIndexType, Vec1},
};

use crate::{
    ballot_style::{
        ArcBallotStyleInfo_or_ArcBallotStyle, BallotStyle, BallotStyleIndex, BallotStyleInfo,
        BallotStyleTrait, inform_bx_ballot_style_infos_of_their_indices,
    },
    ciphertext::{Ciphertext, CiphertextIndex},
    contest::{Contest, ContestIndex},
    contest_option::{ContestOption, ContestOptionIndex},
    errors::{EgError, EgResult},
    label::{LabeledItem, validate_label},
    preencrypted_ballots::{
        ArcPreencryptedBallotsConfigInfo_or_ArcPreencryptedBallotsConfig,
        PreencryptedBallotsConfig, PreencryptedBallotsConfigInfo, PreencryptedBallotsConfigTrait,
    },
    resource::ProduceResource,
    selection_limits::{
        ContestSelectionLimit, EffectiveContestSelectionLimit, EffectiveOptionSelectionLimit,
        OptionSelectionLimit,
    },
    serializable::SerializableCanonical,
    validatable::Validated,
    voting_device::VotingDeviceInformationSpec,
};

#[allow(unused_imports)]
use crate::resource::ProduceResourceExt;

//=================================================================================================|

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
#[derive(Debug, Clone, // PartialEq, Eq,
    serde::Serialize)]
pub struct ElectionManifestInfo {
    /// A descriptive label for this election.
    pub label: String,

    /// Record Undervoted Contest Condition
    ///
    /// EGDS 2.1.0 Sec 3.1.3 pg. 18
    ///
    /// "A manifest may specify whether the fact that a contest was undervoted should be recorded
    /// for public verification."
    ///
    /// Note that this may be overridden on a per-contest basis.
    pub record_undervoted_contest_condition: bool,

    /// Record Undervote Difference
    ///
    /// EGDS 2.1.0 Sec 3.1.3 pg. 18
    ///
    /// "A manifest may specify whether the total number of undervotes,
    /// i.e., the difference between the number of selections the voter made and the contest
    /// selection limit(or in other words, the contest net undervote count) for each contest should
    /// be recorded for public verification."
    ///
    /// Note that this may be overridden on a per-contest basis.
    pub record_undervote_difference: bool,

    /// Preencrypted Ballots Configuration (Optional)
    ///
    /// If `None`, the PreencryptedBallots feature is not enabled.
    ///
    /// EGDS 2.1.0 Sec 4 pg. 57
    ///
    /// "Pre-Encrypted Ballots (Optional)"
    #[serde(rename = "preencrypted_ballots")]
    pub opt_preencrypted_ballots_config:
        Option<ArcPreencryptedBallotsConfigInfo_or_ArcPreencryptedBallotsConfig>,

    /// All the [`Contest`]s in the election.
    pub contests: Vec1<Contest>,

    /// All the [`BallotStyle`]s of the election.
    pub ballot_styles: Vec1<ArcBallotStyleInfo_or_ArcBallotStyle>,

    /// EGDS 2.1.0 Sec 3.4.3 - Voting Device Information
    ///
    /// The manifest specifies which data is to be included in the `S_device` string
    /// which is hashed to produce the [`VotingDeviceInformationHash`], `H_DI`.
    pub voting_device_information_spec: Arc<VotingDeviceInformationSpec>,
}

impl ElectionManifestInfo {
    /// Returns the number of [`Contest`]s.
    pub fn qty_contests(&self) -> EgResult<ContestIndex> {
        Ok(ContestIndex::try_from_one_based_index(self.contests.len())?)
    }

    /// Returns the number of [`BallotStyle`]s.
    pub fn qty_ballot_styles(&self) -> EgResult<BallotStyleIndex> {
        let qty_ballot_styles =
            BallotStyleIndex::try_from_one_based_index(self.ballot_styles.len())?;
        Ok(qty_ballot_styles)
    }
}

crate::impl_knows_friendly_type_name! { ElectionManifestInfo }

crate::impl_Resource_for_simple_ElectionDataObjectId_info_type! {
ElectionManifestInfo, ElectionManifest }

impl SerializableCanonical for ElectionManifestInfo {}

impl<'de> Deserialize<'de> for ElectionManifestInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Error, MapAccess};
        use strum::{IntoStaticStr, VariantNames};

        #[derive(Deserialize, IntoStaticStr, VariantNames)]
        #[serde(field_identifier)]
        #[allow(non_camel_case_types)]
        enum Field {
            label,
            record_undervoted_contest_condition,
            record_undervote_difference,
            preencrypted_ballots,
            contests,
            ballot_styles,
            voting_device_information_spec,
        }

        struct ElectionManifestInfoVisitor;

        impl<'de> de::Visitor<'de> for ElectionManifestInfoVisitor {
            type Value = ElectionManifestInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("ElectionManifest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let Some((Field::label, label)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::label.into()));
                };

                let Some((
                    Field::record_undervoted_contest_condition,
                    record_undervoted_contest_condition,
                )) = map.next_entry()?
                else {
                    return Err(V::Error::missing_field(
                        Field::record_undervoted_contest_condition.into(),
                    ));
                };

                let Some((Field::record_undervote_difference, record_undervote_difference)) =
                    map.next_entry()?
                else {
                    return Err(V::Error::missing_field(
                        Field::record_undervote_difference.into(),
                    ));
                };

                let Some((Field::preencrypted_ballots, opt_preencrypted_ballots_config)) =
                    map.next_entry::<Field, Option<Arc<PreencryptedBallotsConfigInfo>>>()?
                else {
                    return Err(V::Error::missing_field(Field::preencrypted_ballots.into()));
                };

                let Some((Field::contests, contests)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::contests.into()));
                };

                // Deserialize the `BallotStyleInfo`s and immediately inform them of their indices.
                let ballot_styles: Vec1<ArcBallotStyleInfo_or_ArcBallotStyle> = {
                    let Some((Field::ballot_styles, v_bxbsi)) =
                        map.next_entry::<Field, Vec<Box<BallotStyleInfo>>>()?
                    else {
                        return Err(V::Error::missing_field(Field::ballot_styles.into()));
                    };

                    let mut v1_bxbsi = Vec1::try_from(v_bxbsi).map_err(V::Error::custom)?;

                    inform_bx_ballot_style_infos_of_their_indices(&mut v1_bxbsi)
                        .map_err(V::Error::custom)?;

                    // Convert to `Vec1<ArcBallotStyleInfo_or_ArcBallotStyle>`
                    v1_bxbsi.map_into(|bxbsi| Either::Left(bxbsi.into()))
                };

                let voting_device_information_spec = {
                    let Some((
                        Field::voting_device_information_spec,
                        voting_device_information_spec,
                    )) = map.next_entry()?
                    else {
                        return Err(V::Error::missing_field(
                            Field::voting_device_information_spec.into(),
                        ));
                    };
                    Arc::new(voting_device_information_spec)
                };

                Ok(ElectionManifestInfo {
                    label,
                    record_undervoted_contest_condition,
                    record_undervote_difference,
                    opt_preencrypted_ballots_config: opt_preencrypted_ballots_config
                        .map(Either::Left),
                    contests,
                    ballot_styles,
                    voting_device_information_spec,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("ElectionManifestInfo", FIELDS, ElectionManifestInfoVisitor)
    }
}

crate::impl_validatable_validated! {
    version_1:
    src: ElectionManifestInfo, produce_resource => EgResult<ElectionManifest> {
        //? let election_parameters = produce_resource.election_parameters().await?.as_ref();

        let ElectionManifestInfo {
            label,
            record_undervoted_contest_condition,
            record_undervote_difference,
            opt_preencrypted_ballots_config,
            contests,
            ballot_styles,
            voting_device_information_spec,
        } = src;

        //----- Validate `label`.

        // EGDS 2.1.0 S3.1.3.b EGRI accepts ElectionManifest labels composed of printable characters and (internal, non-contiguous) 0x20 space characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels that contain line break characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels that have leading or trailing whitespace
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels that contain contiguous sequences of whitespace other than a single 0x20 space
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels that contain special characters (Unicode Category Cc, Cf, Zs, Zl, Zp, or Cs)
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels having no printable characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels that decode to a Unicode malformed surrogate pair (Unicode Category Cs). See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603)
        validate_label(label.as_str(), LabeledItem::ElectionManifest)?;

        //----- Validate `record_undervoted_contest_condition`.

        // This is a `bool` and either value is valid.

        //----- Validate `record_undervote_difference`.

        // This is a `bool` and either value is valid.

        //----- Validate `opt_preencrypted_ballots_config`.

        let opt_preencrypted_ballots_config = if let Some(pebc_or_pebci) = opt_preencrypted_ballots_config {
            let arc_pebc = match pebc_or_pebci {
                Either::Left(arc_pebci) => {
                    // Attempt to validate the `PreencryptedBallotConfigInfo` to a proper `PreencryptedBallotConfig`.
                    let pebc = PreencryptedBallotsConfig::try_validate_from_arc(arc_pebci.clone(), produce_resource)?;
                    Arc::new(pebc)
                }
                Either::Right(arc_pebc) => arc_pebc,
            };
            Some(arc_pebc)
        } else {
            None
        };

        //----- Validate `contests`.

        let cnt_contests = contests.len();

        for (contest_ix, contest) in contests.enumerate() {
            contest.validate(contest_ix)?;

            //? TODO    if the stated selection limit is greater than the sum of the option selection limits, issue a warning.
            //? TODO    if the contest has a selection limit of 0, issue a warning
            //? TODO    For each option
            //? TODO       if the option has a selection limit of 0, issue a warning

            //? TODO if the contest is present in zero ballot styles, issue a warning.
        }

        // EGDS 2.1.0 S3.1.3.a EGRI rejects any ElectionManifest containing duplicate labels for Contests
        for (contest_ix_a, contest_a) in contests.enumerate().skip(1) {
            for (contest_ix_b, contest_b) in contests.enumerate().take(contest_ix_a.as_quantity() - 1) {
                if contest_a.label == contest_b.label {
                    let duplicate_label = Cow::Borrowed(contest_a.label.as_str());
                    let duplicate_label = truncate_text(duplicate_label, 40).to_string();
                    let e = EgError::ContestsHaveDuplicateLabels {
                        contest_ix_a: contest_ix_b,
                        contest_ix_b: contest_ix_a,
                        duplicate_label,
                    };
                    trace!("{e}");
                    return Err(e);
                }
            }
        }

        //----- Validate `ballot_styles`.

        let (ballot_styles, cnt_ballot_styles) = {
            let v1_arcbsi_or_arcbs = ballot_styles;

            let cnt_ballot_styles = v1_arcbsi_or_arcbs.len();

            let mut v1_arcbs: Vec1<Arc<BallotStyle>> = Vec1::with_capacity(cnt_ballot_styles);
            for (ballot_style_ix, arcbsi_or_arcbs) in v1_arcbsi_or_arcbs.enumerate_into() {
                let arc_bs = match arcbsi_or_arcbs {
                    Either::Left(arc_bsi) => {
                        // Verify it has the correct index.
                        arc_bsi.validate_ballot_style_ix(ballot_style_ix)?;

                        // Attempt to validate the BallotStyleInfo to a proper BallotStyle.
                        let ballot_style = BallotStyle::try_validate_from_arc(arc_bsi, produce_resource)?;
                        Arc::new(ballot_style)
                    }
                    Either::Right(arc_bs) => {
                        // Verify it has the correct index.
                        arc_bs.validate_ballot_style_ix(ballot_style_ix)?;

                        arc_bs
                    },
                };

                v1_arcbs.try_push(arc_bs)?;
            }

            (v1_arcbs, cnt_ballot_styles)
        };

        // S3.1.3.f EGRI rejects any Election Manifest having a Ballot Style with a ContestIndex list containing a
        // Contest Index that does not refer to a contest in the Election Manifest.

        for ballot_style in ballot_styles.iter() {
            ballot_style.validate_contest_indexes(&contests)?;
        }

        //? TODO S3.1.3.f Every Ballot Style defines a label unique across all Ballot Styles in the manifest

        //----- Validate `voting_device_information_spec`.

        //? TODO

        //----- Construct the object from the validated data.

        let mut self_ = ElectionManifest {
            label,
            record_undervoted_contest_condition,
            record_undervote_difference,
            opt_preencrypted_ballots_config,
            contests,
            ballot_styles,
            voting_device_information_spec,
        };

        // Inform the contained objects of their indices.
        self_.inform_contests_and_options_of_their_indices()?;

        //----- Return the fully constructed and validated `ElectionManifest` object.

        Ok(self_)
    }
}

impl From<ElectionManifest> for ElectionManifestInfo {
    /// Convert from ElectionManifest back to a ElectionManifestInfo for re-validation.
    fn from(src: ElectionManifest) -> Self {
        let ElectionManifest {
            label,
            record_undervoted_contest_condition,
            record_undervote_difference,
            opt_preencrypted_ballots_config,
            contests,
            ballot_styles,
            voting_device_information_spec,
        } = src;

        let ballot_styles: Vec1<ArcBallotStyleInfo_or_ArcBallotStyle> =
            ballot_styles.map_into(Either::Right);

        let opt_preencrypted_ballots_config = opt_preencrypted_ballots_config.map(Either::Right);

        Self {
            label,
            record_undervoted_contest_condition,
            record_undervote_difference,
            opt_preencrypted_ballots_config,
            contests,
            ballot_styles,
            voting_device_information_spec,
        }
    }
}

/// The election manifest.
#[derive(Clone, serde::Serialize)]
pub struct ElectionManifest {
    label: String,
    record_undervoted_contest_condition: bool,
    record_undervote_difference: bool,

    #[serde(rename = "preencrypted_ballots")]
    opt_preencrypted_ballots_config: Option<Arc<PreencryptedBallotsConfig>>,

    contests: Vec1<Contest>,
    ballot_styles: Vec1<Arc<BallotStyle>>,
    voting_device_information_spec: Arc<VotingDeviceInformationSpec>,
}

impl ElectionManifest {
    /// Returns access to the label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Record Undervoted Contest Condition
    ///
    /// EGDS 2.1.0 Sec 3.1.3 pg. 18:
    ///
    /// "A manifest may specify whether the fact that a contest was undervoted should be recorded
    /// for public verification."
    ///
    /// Note that this may be overridden on a per-contest basis.
    pub fn record_undervoted_contest_condition(&self) -> bool {
        self.record_undervoted_contest_condition
    }

    /// Record Undervote Difference
    ///
    /// EGDS 2.1.0 Sec 3.1.3 pg. 18
    ///
    /// "A manifest may specify whether the total number of undervotes,
    /// i.e., the difference between the number of selections the voter made and the contest selection limit
    /// (or in other words, the contest net undervote count) for each contest should be recorded for public
    /// verification."
    ///
    /// Note that this may be overridden on a per-contest basis.
    pub fn record_undervote_difference(&self) -> bool {
        self.record_undervote_difference
    }

    /// Preencrypted Ballots Configuration (Optional)
    ///
    /// If `None`, the PreencryptedBallots feature is not enabled.
    ///
    /// EGDS 2.1.0 Sec 4 pg. 57
    ///
    /// "Pre-Encrypted Ballots (Optional)"
    pub fn opt_preencrypted_ballots_config(&self) -> &Option<Arc<PreencryptedBallotsConfig>> {
        &self.opt_preencrypted_ballots_config
    }

    /// Returns the number of [`Contest`]s.
    pub fn qty_contests(&self) -> EgResult<ContestIndex> {
        let qty_contests = ContestIndex::try_from_one_based_index(self.contests.len())?;
        Ok(qty_contests)
    }

    /// Returns access to the collection of [`Contest`]s.
    ///
    /// If you just want a specific contest:
    /// - If you know the ballot style, consider using `ballot_style.get_contest()`.
    /// - Otherwise, `election_manifest.get_contest_without_checking_ballot_style()`.
    pub fn contests(&self) -> &Vec1<Contest> {
        &self.contests
    }

    /// Returns the number of [`BallotStyle`]s.
    pub fn qty_ballot_styles(&self) -> EgResult<BallotStyleIndex> {
        let qty_ballot_styles =
            BallotStyleIndex::try_from_one_based_index(self.ballot_styles.len())?;
        Ok(qty_ballot_styles)
    }

    /// Returns access to the collection of [`BallotStyle`]s.
    ///
    /// If you just want a specific ballot style, consider using [`.get_ballot_style()`].
    pub fn ballot_styles(&self) -> &Vec1<Arc<BallotStyle>> {
        &self.ballot_styles
    }

    /// Returns a ref to the [`BallotStyle`] at the specified [`BallotStyleIndex`].
    ///
    /// Verifies that the resulting `BallotStyle`:
    /// - knows its `BallotStyleIndex`, and
    /// - its `BallotStyleIndex` matches the one by which it was just retrieved.
    ///
    pub fn get_ballot_style_validate_ix(
        &self,
        ballot_style_ix: BallotStyleIndex,
    ) -> EgResult<&BallotStyle> {
        let bs = self.ballot_styles.get(ballot_style_ix).ok_or(
            EgError::BallotStyleNotInElectionManifest {
                ballot_style_ix,
                election_manifest_cnt_ballot_styles: self.ballot_styles.len(),
            },
        )?;

        // Don't give it the `ElectionManifest`. Since we already know it was
        // retrieved from it at the specified index, the additional work it does is not useful.
        bs.get_validated_ballot_style_ix(Some(ballot_style_ix), None)?;

        Ok(bs)
    }

    /// EGDS 2.1.0 Sec 3.4.3 - Voting Device Information
    ///
    /// The manifest specifies which data is to be included in the `S_device` string
    /// which is hashed to produce the [`VotingDeviceInformationHash`], `H_DI`.
    pub fn voting_device_information_spec(&self) -> &VotingDeviceInformationSpec {
        &self.voting_device_information_spec
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

    /// Inform each contest of its index.
    /// Also, inform the contest options of their indices.
    fn inform_contests_and_options_of_their_indices(&mut self) -> EgResult<()> {
        for (contest_ix, contest) in self.contests.enumerate_mut() {
            contest.inform_contest_of_its_index_and_its_options_of_theirs(contest_ix)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for ElectionManifest {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ElectionManifest {
            label,
            record_undervoted_contest_condition,
            record_undervote_difference,
            opt_preencrypted_ballots_config,
            contests,
            ballot_styles,
            voting_device_information_spec,
        } = self;
        let alternate = f.alternate();
        let mut ds = f.debug_struct("ElectionManifest");
        if alternate {
            ds.field("label", label);
            ds.field(
                "record_undervoted_contest_condition",
                record_undervoted_contest_condition,
            );
            ds.field("record_undervote_difference", record_undervote_difference);
            ds.field(
                "opt_preencrypted_ballots_config",
                opt_preencrypted_ballots_config,
            );
            ds.field("contests", contests);
            ds.field("ballot_styles", ballot_styles);
            ds.field(
                "voting_device_information_spec",
                voting_device_information_spec,
            );
            ds.finish()
        } else {
            let label = util::text::truncate_text(label.into(), 72);
            ds.field("label", &label);
            ds.finish_non_exhaustive()
        }
    }
}

impl SerializableCanonical for ElectionManifest {}

crate::impl_knows_friendly_type_name! { ElectionManifest }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! {
    ElectionManifest, ElectionManifest
}

// Unit tests for the ElectionManifest.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod t {
    use std::io::Cursor;

    use anyhow::Context;
    use insta::{assert_ron_snapshot, assert_snapshot};
    use serde_json::{Value as JsonValue, json};

    use super::*;
    use crate::{
        eg::Eg,
        loadable::{LoadableFromStdIoReadValidatable, LoadableFromStdIoReadValidated},
        serializable::{SerializableCanonical, SerializablePretty},
    };

    pub fn common_test_election_manifest_jv(cnt_contests: usize) -> JsonValue {
        let contests: Vec<JsonValue> = (1..=cnt_contests)
            .map(|ix1| {
                json!({
                    "label": format!("Contest {ix1}"),
                    "options": [ ]
                })
            })
            .collect();

        json!({
            "label": "General Election",
            "record_undervoted_contest_condition": false,
            "record_undervote_difference": false,
            "preencrypted_ballots": null,
            "contests": contests,
            "ballot_styles": [ ],
            "voting_device_information_spec": { "DoesNotContainVotingDeviceInformation": { } }
        })
    }

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::election_manifest::t::t1",
            );
            let eg = eg.as_ref();

            let election_manifest = eg
                .election_manifest()
                .await
                .context("producing ElectionManifest")
                .inspect_err(|e| println!("Error: {e:#?}"))
                .unwrap();

            // Pretty
            {
                let json_pretty = {
                    let mut buf = Cursor::new(vec![0u8; 0]);
                    election_manifest.to_stdiowrite_pretty(&mut buf).unwrap();
                    buf.into_inner()
                };
                assert!(json_pretty.len() > 6);
                assert_eq!(*json_pretty.last().unwrap(), b'\n');

                let election_manifest_from_json_pretty =
                    ElectionManifest::from_stdioread_validated(
                        &mut Cursor::new(json_pretty.clone()),
                        eg,
                    )
                    .inspect_err(|e| {
                        println!("Error: {e:#?}");
                        let buf = Cursor::new(json_pretty.clone());
                        use std::io::BufRead;
                        for (ix, line_result) in buf.lines().enumerate() {
                            let line = line_result.unwrap_or_else(|e| format!("Error: {e:#?}"));
                            println!("line {:5}: {line}", ix + 1);
                        }
                    })
                    .unwrap();
                assert_eq!(
                    election_manifest.contests().len(),
                    election_manifest_from_json_pretty.contests().len()
                );

                let json_pretty_2 = {
                    let mut buf = Cursor::new(vec![0u8; 0]);
                    election_manifest_from_json_pretty
                        .to_stdiowrite_pretty(&mut buf)
                        .unwrap();
                    buf.into_inner()
                };

                assert_eq!(json_pretty, json_pretty_2);
            }

            // Canonical
            {
                let canonical_bytes = election_manifest.to_canonical_bytes().unwrap();
                assert!(canonical_bytes.len() > 5);
                assert_ne!(canonical_bytes[canonical_bytes.len() - 1], b'\n');
                assert_ne!(canonical_bytes[canonical_bytes.len() - 1], 0x00);

                let mut cursor = Cursor::new(canonical_bytes);
                let election_manifest_from_canonical_bytes =
                    ElectionManifest::from_stdioread_validated(&mut cursor, eg).unwrap();
                assert_eq!(
                    election_manifest.contests().len(),
                    election_manifest_from_canonical_bytes.contests().len()
                );
                let canonical_bytes = cursor.into_inner();

                let canonical_bytes_2 = election_manifest_from_canonical_bytes
                    .to_canonical_bytes()
                    .unwrap();
                assert_eq!(canonical_bytes, canonical_bytes_2);
            }
        });
    }

    #[test_log::test]
    fn t2() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::election_manifest::t::t2",
            );
            let eg = eg.as_ref();

            let election_manifest = eg
                .election_manifest()
                .await
                .context("producing ElectionManifest")
                .inspect_err(|e| println!("Error: {e:#?}"))
                .unwrap();

            assert_snapshot!(election_manifest.record_undervoted_contest_condition(), @"false");

            assert_snapshot!(election_manifest.contests.get(1.try_into().unwrap()).unwrap().effective_record_undervoted_contest_condition(&election_manifest), @"false");
            assert_snapshot!(election_manifest.contests.get(2.try_into().unwrap()).unwrap().effective_record_undervoted_contest_condition(&election_manifest), @"false");
            assert_snapshot!(election_manifest.contests.get(3.try_into().unwrap()).unwrap().effective_record_undervoted_contest_condition(&election_manifest), @"true");
        });
    }

    #[test_log::test]
    fn t3() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::election_manifest::t::t2",
            );
            let eg = eg.as_ref();

            let election_manifest = eg
                .election_manifest()
                .await
                .context("producing ElectionManifest")
                .inspect_err(|e| println!("Error: {e:#?}"))
                .unwrap();

            assert_snapshot!(election_manifest.record_undervote_difference(), @"true");

            assert_snapshot!(election_manifest.contests.get(3.try_into().unwrap()).unwrap().effective_record_undervote_difference(&election_manifest), @"true");
            assert_snapshot!(election_manifest.contests.get(4.try_into().unwrap()).unwrap().effective_record_undervote_difference(&election_manifest), @"true");
            assert_snapshot!(election_manifest.contests.get(5.try_into().unwrap()).unwrap().effective_record_undervote_difference(&election_manifest), @"false");
        });
    }

    #[test_log::test]
    fn t4() {
        // EGDS 2.1.0 S3.1.3.a EGRI rejects any ElectionManifest containing duplicate labels for Contests

        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::election_manifest::t::t4",
            );
            let eg = eg.as_ref();

            let mut em_jv = common_test_election_manifest_jv(2);
            em_jv["contests"][0]["label"] = json!("Duplicate Contest Label");
            em_jv["contests"][1]["label"] = json!("Duplicate Contest Label");

            let em_js = serde_json::to_string_pretty(&em_jv).unwrap();

            let em_info = ElectionManifestInfo::from_json_str_validatable(&em_js).unwrap();

            let validate_result = ElectionManifest::try_validate_from(em_info, eg);

            let expected_error = EgError::ContestsHaveDuplicateLabels {
                contest_ix_a: ContestIndex::try_from(1).unwrap(),
                contest_ix_b: ContestIndex::try_from(2).unwrap(),
                duplicate_label: "Duplicate Contest Label".to_string(),
            };
            assert_eq!(validate_result.unwrap_err(), expected_error);
        });
    }

    #[test_log::test]
    fn t5() {
        // EGDS 2.1.0 S3.1.3.a EGRI rejects any ElectionManifest containing duplicate labels for ContestOptions in any Contest

        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::election_manifest::t::t5",
            );
            let eg = eg.as_ref();

            let mut em_jv = common_test_election_manifest_jv(1);
            em_jv["contests"][0]["options"] = json!([
                { "label": "Other Contest Option Label A" },
                { "label": "Duplicate Contest Option Label" },
                { "label": "Duplicate Contest Option Label" },
                { "label": "Other Contest Option Label B" }
            ]);

            let em_js = serde_json::to_string_pretty(&em_jv).unwrap();

            let em_info = ElectionManifestInfo::from_json_str_validatable(&em_js).unwrap();

            let validate_result = ElectionManifest::try_validate_from(em_info, eg);

            let expected_error = EgError::ContestOptionsHaveDuplicateLabels {
                contest_ix: ContestIndex::try_from(1).unwrap(),
                contest_option_ix_a: ContestOptionIndex::try_from(2).unwrap(),
                contest_option_ix_b: ContestOptionIndex::try_from(3).unwrap(),
                duplicate_label: "Duplicate Contest Option Label".to_string(),
            };
            assert_eq!(validate_result.unwrap_err(), expected_error);
        });
    }

    async fn test_election_label(election_label: &str) -> EgResult<()> {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::election_manifest::t::test_election_label",
        );
        let eg = eg.as_ref();

        let mut em_jv = common_test_election_manifest_jv(0);
        em_jv["label"] = json!(election_label);

        let em_js = serde_json::to_string_pretty(&em_jv).unwrap();

        let em_info = ElectionManifestInfo::from_json_str_validatable(&em_js).unwrap();

        ElectionManifest::try_validate_from(em_info, eg).map(|_| ())
    }

    #[test_log::test]
    fn t6() {
        async_global_executor::block_on(async {
            // EGDS 2.1.0 S3.1.3.b EGRI accepts ElectionManifest labels composed of printable characters and (internal, non-contiguous) 0x20 space characters
            assert_ron_snapshot!(test_election_label(
                    "ElectionManifest label composed of printable characters and (internal, non-contiguous) 0x20 space characters"
                ).await,
                @"Ok(())");

            // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels that contain line break characters
            assert_ron_snapshot!(test_election_label(
                    "ElectionManifest label that contains\nline\nbreak characters"
                ).await,
                @r#"
            Err(LabelError(NotAllowedChar(CharNotAllowedInText(
              labeled_item: ElectionManifest,
              char_ix1: 37,
              byte_offset: 36,
              unicode_property: Control,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels that have leading or trailing whitespace
            assert_ron_snapshot!(test_election_label(
                    " ElectionManifest label that has leading whitespace"
                ).await,
                @r#"
            Err(LabelError(LeadingOrTrailingWhitespace((Leading, CharNotAllowedInText(
              labeled_item: ElectionManifest,
              char_ix1: 1,
              byte_offset: 0,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            )))))"#);

            assert_ron_snapshot!(test_election_label(
                    "ElectionManifest label that has trailing whitespace "
                ).await,
                @r#"
            Err(LabelError(LeadingOrTrailingWhitespace((Trailing, CharNotAllowedInText(
              labeled_item: ElectionManifest,
              char_ix1: 52,
              byte_offset: 51,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            )))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels that contain contiguous sequences of whitespace other than a single 0x20 space
            assert_ron_snapshot!(test_election_label(
                    "ElectionManifest label that contains  contiguous sequences of whitespace"
                ).await,
                @r#"
            Err(LabelError(ContiguousWhitespace(CharNotAllowedInText(
              labeled_item: ElectionManifest,
              char_ix1: 38,
              byte_offset: 37,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels that contain special characters (Unicode Category Cc, Cf, Zs, Zl, Zp, or Cs)
            // 0x002028 - LINE SEPARATOR - 'Zl'
            assert_ron_snapshot!(test_election_label(
                    "ElectionManifest\u{002028}label that contains a special character"
                ).await,
                @r#"
            Err(LabelError(NotAllowedChar(CharNotAllowedInText(
              labeled_item: ElectionManifest,
              char_ix1: 17,
              byte_offset: 16,
              unicode_property: LineSeparator,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels having no printable characters
            assert_ron_snapshot!(test_election_label(
                    ""
                ).await,
                @"Err(LabelError(NoPossiblyPrintableCharacters(ElectionManifest)))");

            assert_ron_snapshot!(test_election_label(
                    "\u{00200C}"
                ).await,
                @"Err(LabelError(NoPossiblyPrintableCharacters(ElectionManifest)))");

            //? TODO EGDS 2.1.0 S3.1.3.b EGRI rejects ElectionManifest labels that decode to a Unicode malformed surrogate pair (Unicode Category Cs). See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603)
            //? TODO
        });
    }
}
