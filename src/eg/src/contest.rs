// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]

use std::borrow::Cow;

#[allow(unused_imports)]
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
    contest_option::{ContestOption, ContestOptionIndex},
    election_manifest::ElectionManifest,
    errors::{EgError, EgResult},
    label::{LabeledItem, validate_label},
    selection_limits::{
        ContestSelectionLimit, EffectiveContestSelectionLimit, EffectiveOptionSelectionLimit,
    },
};

#[allow(unused_imports)]
use crate::resource::ProduceResourceExt;

//=================================================================================================|

/// A 1-based index of a [`Contest`] in the order that
/// the [`Contest`](crate::contest::Contest) is defined in the
/// [`ElectionManifest`](crate::election_manifest::ElectionManifest).
///
/// Same type as:
///
/// - [`ContestIndex`](crate::contest::ContestIndex)
/// - [`ContestTalliesIndex`](crate::contest_data_fields_tallies::ContestTalliesIndex)
pub type ContestIndex = Index<Contest>;

impl HasIndexType for Contest {
    type IndexTypeParam = Contest;
}

//-------------------------------------------------------------------------------------------------|

/// A contest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(serde::Serialize, serde::Deserialize)]
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

    /// Record Undervoted Contest Condition
    ///
    /// EGDS 2.1.0 Sec 3.1.3 pg. 18
    ///
    /// "A manifest may specify whether the fact that a contest was undervoted should be recorded
    /// for public verification."
    ///
    /// Note that this optional per-[`Contest`] setting overrides the [`ElectionManifest`]-level setting.
    #[serde(
        default,
        rename = "record_undervoted_contest_condition",
        skip_serializing_if = "Option::is_none"
    )]
    pub opt_record_undervoted_contest_condition: Option<bool>,

    //xx
    #[serde(
        default,
        rename = "record_undervote_difference",
        skip_serializing_if = "Option::is_none"
    )]
    pub opt_record_undervote_difference: Option<bool>,

    /// The contest options, e.g. "candidates".
    /// The order and quantity of contest options matches the contest's definition in the
    /// [`ElectionManifest`].
    #[serde(rename = "options")]
    pub contest_options: Vec1<ContestOption>,
}

impl Contest {
    /// Returns a ref to the [`ContestOption`] at index `ix`.
    pub fn get_contest_option(&self, ix: ContestOptionIndex) -> EgResult<&ContestOption> {
        self.contest_options
            .get(ix)
            .ok_or(EgError::ContestOptionIndexNotInContest(ix))
    }

    /// The number of Contest Option Data Fields for this [`Contest`], not including any non-selectable or
    /// system-assigned additional data fields.
    ///
    /// This value is the required length of the
    /// [`ContestOptionFieldsPlaintexts`](crate::contest_data_fields_plaintexts::ContestDataFieldsPlaintexts)
    /// that should be supplied in the
    /// [`VoterSelectionsPlaintext`](crate::voter_selections_plaintext::VoterSelectionsPlaintext)
    /// for this contest .
    pub fn qty_contest_option_data_fields(&self) -> usize {
        self.contest_options.len()
    }

    /// The number of (non-selectable) additional data fields used for this [`Contest`].
    pub fn qty_additional_non_selectable_option_data_fields(&self) -> usize {
        //? TODO determine this once policy of recording (over|under)vote[ds], is fully defined.
        0
    }

    /// The total number of data fields used for this [`Contest`]. I.e., the total number of
    /// [`Ciphertexts`](crate::ciphertext::Ciphertext) recorded for this `Contest` on a
    /// [`Ballot`](crate::ballot::Ballot) of a [`BallotStyle`] containing it.
    ///
    /// This is simply the sum of `num_selectable_option_data_fields()` and
    /// `num_additional_non_selectable_option_data_fields()`.
    pub fn qty_data_fields(&self) -> usize {
        self.qty_contest_option_data_fields()
            + self.qty_additional_non_selectable_option_data_fields()
    }

    /// The effective selection limit for this [`Contest`].
    ///
    /// This is the smaller of this contest's selection limit and the sum of the selection limits
    /// of all this `Contest`'s options'.
    pub fn effective_contest_selection_limit(&self) -> EgResult<EffectiveContestSelectionLimit> {
        EffectiveContestSelectionLimit::figure(self)
    }

    /// The effective setting of 'Record Undervoted Contest Condition' for this [`Contest`].
    ///
    /// See EGDS 2.1.0 Sec 3.1.3 pg. 18
    pub fn effective_record_undervoted_contest_condition(
        &self,
        election_manifest: &ElectionManifest,
    ) -> bool {
        self.opt_record_undervoted_contest_condition
            .unwrap_or_else(|| election_manifest.record_undervoted_contest_condition())
    }

    /// The effective setting of 'Record Undervote Difference' for this [`Contest`].
    ///
    /// See EGDS 2.1.0 Sec 3.1.3 pg. 18
    pub fn effective_record_undervote_difference(
        &self,
        election_manifest: &ElectionManifest,
    ) -> bool {
        self.opt_record_undervote_difference
            .unwrap_or_else(|| election_manifest.record_undervote_difference())
    }

    /// The effective selection limits for every [`ContestOption`] of this [`Contest`].
    pub fn figure_options_effective_selection_limits(
        &self,
    ) -> EgResult<Vec1<EffectiveOptionSelectionLimit>> {
        let mut v = Vec::<EffectiveOptionSelectionLimit>::with_capacity(self.contest_options.len());
        for contest_option in self.contest_options.iter() {
            let esl = contest_option.effective_selection_limit(self)?;
            v.push(esl);
        }
        v.try_into().map_err(Into::into)
    }

    /// Validates the Contest internally as much as practical. But since it doesn't have access
    /// to other contests in the ElectionManifest, it won't be able to check for things like duplicate labels.
    pub fn validate(&self, contest_ix: ContestIndex) -> EgResult<()> {
        // Validate the [`Contest`] Label.
        // EGDS 2.1.0 S3.1.3.b EGRI accepts Contest labels composed of printable characters and (internal, non-contiguous) 0x20 space characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels that contain line break characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels that have leading or trailing whitespace
        // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels that contain contiguous sequences of whitespace other than a single 0x20 space
        // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels that contain special characters (Unicode Category Cc, Cf, Zs, Zl, Zp, or Cs)
        // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels having no printable characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels that decode to a Unicode malformed surrogate pair (Unicode Category Cs). See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603)
        validate_label(self.label.as_str(), LabeledItem::Contest(contest_ix))?;

        let contest_options = &self.contest_options;

        // Validate the [`ContestOptions`].
        for (contest_option_ix, contest_option) in contest_options.enumerate() {
            contest_option.validate(self, contest_ix, contest_option_ix)?;
        }

        // EGDS 2.1.0 S3.1.3.a EGRI rejects any ElectionManifest containing duplicate labels for [`ContestOption`]s in any contest
        for (contest_option_ix_a, contest_option_a) in contest_options.enumerate().skip(1) {
            let options_take_some = contest_options
                .enumerate()
                .take(contest_option_ix_a.as_quantity() - 1);
            for (contest_option_ix_b, contest_option_b) in options_take_some {
                if contest_option_a.label == contest_option_b.label {
                    let duplicate_label = Cow::Borrowed(contest_option_a.label.as_str());
                    let duplicate_label = truncate_text(duplicate_label, 40).to_string();
                    let e = EgError::ContestOptionsHaveDuplicateLabels {
                        contest_ix,
                        contest_option_ix_a: contest_option_ix_b,
                        contest_option_ix_b: contest_option_ix_a,
                        duplicate_label,
                    };
                    trace!("{e}");
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Informs the [`Contest`] of its [`ContestIndex`], and the [`ContestOption`](ContestOption)s
    /// of their indices.
    pub(crate) fn inform_contest_of_its_index_and_its_options_of_theirs(
        &mut self,
        contest_ix: ContestIndex,
    ) -> EgResult<()> {
        match self.opt_contest_ix {
            Option::Some(contests_contest_ix) => {
                if contests_contest_ix != contest_ix {
                    return Err(EgError::ContestIndexMismatch {
                        contest_ix,
                        contests_contest_ix,
                    });
                }
            }
            Option::None => {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use insta::assert_ron_snapshot;
    use serde_json::json;

    use super::*;
    #[allow(unused_imports)] //? TODO: Remove temp development code
    use crate::{
        eg::Eg,
        election_manifest::{ElectionManifestInfo, t::common_test_election_manifest_jv},
        loadable::{LoadableFromStdIoReadValidatable, LoadableFromStdIoReadValidated},
        serializable::{SerializableCanonical, SerializablePretty},
        validatable::{Validatable, Validated},
    };

    async fn test_contest_label(contest_label: &str) -> EgResult<()> {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::election_manifest::t::test_contest_label",
        );
        let eg = eg.as_ref();

        let mut em_jv = common_test_election_manifest_jv(1);
        em_jv["contests"][0]["label"] = json!(contest_label);

        let em_js = serde_json::to_string_pretty(&em_jv).unwrap();

        let em_info = ElectionManifestInfo::from_json_str_validatable(em_js.as_str()).unwrap();

        ElectionManifest::try_validate_from(em_info, eg).map(|_| ())
    }

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            // EGDS 2.1.0 S3.1.3.b EGRI accepts Contest labels composed of printable characters and (internal, non-contiguous) 0x20 space characters

            assert_ron_snapshot!(test_contest_label(
                "For President and Vice President of The United Realms of Imaginaria"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(test_contest_label(
                "Minister of Elemental Resources"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(test_contest_label(
                "Minister of Arcane Sciences"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(test_contest_label(
                "Minister of Dance"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(test_contest_label(
                "Gränd Cøuncil of Arcáne and Technomägical Affairs"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(test_contest_label(
                "Proposed Amendment No. 1 Equal Representation for Technological and Magical Profeſsions"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(test_contest_label(
                "Privacy Protection in Techno-Magical Communications Act"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(test_contest_label(
                "Public Transport Modernization and Enchantment Proposal"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(test_contest_label(
                "Renewable Ætherwind Infrastructure Initiative"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(test_contest_label(
                "For Librarian-in-Chief of Smoothstone County"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(test_contest_label(
                "Silvërspîre County Register of Deeds Sébastian Moonglôw to be retained"
                ).await,
                @"Ok(())");
        });
    }

    #[test_log::test]
    fn t2() {
        async_global_executor::block_on(async {
            // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels that contain line break characters
            assert_ron_snapshot!(test_contest_label(
                    "Contest\nlabel that contains a line break character"
                ).await,
                @r#"
            Err(LabelError(NotAllowedChar(CharNotAllowedInText(
              labeled_item: Contest(1),
              char_ix1: 8,
              byte_offset: 7,
              unicode_property: Control,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels that have leading or trailing whitespace
            assert_ron_snapshot!(test_contest_label(
                    " Contest label that has leading whitespace"
                ).await,
                @r#"
            Err(LabelError(LeadingOrTrailingWhitespace((Leading, CharNotAllowedInText(
              labeled_item: Contest(1),
              char_ix1: 1,
              byte_offset: 0,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            )))))"#);

            assert_ron_snapshot!(test_contest_label(
                    "Contest label that has trailing whitespace "
                ).await,
                @r#"
            Err(LabelError(LeadingOrTrailingWhitespace((Trailing, CharNotAllowedInText(
              labeled_item: Contest(1),
              char_ix1: 43,
              byte_offset: 42,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            )))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels that contain contiguous sequences of whitespace other than a single 0x20 space
            assert_ron_snapshot!(test_contest_label(
                    "Contest  label that contains a contiguous sequences of whitespace"
                ).await,
                @r#"
            Err(LabelError(ContiguousWhitespace(CharNotAllowedInText(
              labeled_item: Contest(1),
              char_ix1: 9,
              byte_offset: 8,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels that contain special characters (Unicode Category Cc, Cf, Zs, Zl, Zp, or Cs)
            // 0x002028 - LINE SEPARATOR - 'Zl'
            assert_ron_snapshot!(test_contest_label(
                    "Contest\u{002028}label that contains a special character"
                ).await,
                @r#"
            Err(LabelError(NotAllowedChar(CharNotAllowedInText(
              labeled_item: Contest(1),
              char_ix1: 8,
              byte_offset: 7,
              unicode_property: LineSeparator,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels having no printable characters
            assert_ron_snapshot!(test_contest_label(
                    ""
                ).await,
                @"Err(LabelError(NoPossiblyPrintableCharacters(Contest(1))))");

            assert_ron_snapshot!(test_contest_label(
                    "\u{00200C}"
                ).await,
                @"Err(LabelError(NoPossiblyPrintableCharacters(Contest(1))))");

            //? TODO EGDS 2.1.0 S3.1.3.b EGRI rejects Contest labels that decode to a Unicode malformed surrogate pair (Unicode Category Cs). See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603)
            //? TODO
        });
    }
}
