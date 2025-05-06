// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]

#[allow(unused_imports)]
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

//
use util::vec1::HasIndexType;

use crate::{
    ciphertext::{Ciphertext, CiphertextIndex},
    contest::{Contest, ContestIndex},
    errors::{EgError, EgResult},
    label::{LabeledItem, validate_label},
    selection_limits::{
        // ContestSelectionLimit, EffectiveContestSelectionLimit,
        EffectiveOptionSelectionLimit,
        OptionSelectionLimit,
    },
};

#[allow(unused_imports)]
use crate::resource::{ProduceResource, ProduceResourceExt};

//=================================================================================================|

/// A 1-based index of a [`ContestOption`] in the order it is defined within its
/// [`Contest`](crate::contest::Contest) in the
/// [`ElectionManifest`](crate::election_manifest::ElectionManifest).
///
/// Same type as:
///
/// - [`CiphertextIndex`](crate::ciphertext::CiphertextIndex)
/// - [`ContestOptionIndex`](crate::contest_option::ContestOptionIndex)
/// - [`ContestOptionFieldPlaintextIndex`](crate::contest_option_fields::ContestOptionFieldPlaintextIndex)
/// - [`ContestDataFieldIndex` (`contest_data_fields::`)](crate::contest_data_fields::ContestDataFieldIndex)
/// - [`ContestDataFieldCiphertextIndex` (`contest_data_fields_ciphertexts::`)](crate::contest_data_fields_ciphertexts::ContestDataFieldCiphertextIndex)
/// - [`ContestDataFieldPlaintextIndex` (`contest_data_fields_plaintexts::`)](crate::contest_data_fields_plaintexts::ContestDataFieldPlaintextIndex)
/// - [`ContestDataFieldTallyIndex`](crate::contest_data_fields_tallies::ContestDataFieldTallyIndex)
/// - [`EffectiveOptionSelectionLimit`](crate::selection_limits::EffectiveOptionSelectionLimit)
/// - [`ProofRangeIndex`](crate::zk::ProofRangeIndex)
pub type ContestOptionIndex = CiphertextIndex;

impl HasIndexType for ContestOption {
    type IndexTypeParam = Ciphertext;
}

//-------------------------------------------------------------------------------------------------|

/// An option in a [`Contest`].
///
/// This refers to selectable options, and not to any additional data fields.
///
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ContestOption {
    /// The 1-based index of the [`Contest`] to which this contest option belongs.
    #[serde(skip)]
    pub opt_contest_ix: Option<ContestIndex>,

    /// The 1-based index of this [`ContestOption`] within its [`Contest`].
    #[serde(skip)]
    pub opt_contest_option_ix: Option<ContestOptionIndex>,

    /// The label for this [`ContestOption`].
    pub label: String,

    /// The maximum number of selections ("votes") that a voter may apply to this contest option.
    ///
    /// If not specified, the default is `1`.
    #[serde(default, skip_serializing_if = "OptionSelectionLimit::is_default")]
    pub selection_limit: OptionSelectionLimit,
}

impl ContestOption {
    // If we think we know the [`ContestIndex`] of the [`Contest`] containing this [`ContestOption`],
    // verify it matches the what the passed-in containing Contest believes its [`ContestIndex`] to be.
    pub fn validate_contest_ix_if_known(&self, containing_contest: &Contest) -> EgResult<()> {
        if let (Some(contestoption_contest_ix), Some(containing_contest_ix)) =
            (self.opt_contest_ix, containing_contest.opt_contest_ix)
        {
            if contestoption_contest_ix != containing_contest_ix {
                return Err(match self.opt_contest_option_ix {
                    Option::Some(contest_option_ix) => {
                        EgError::ContestOptionActuallyInDifferentContest {
                            contest_option_ix,
                            containing_contest_ix,
                            contestoption_contest_ix,
                        }
                    }
                    Option::None => EgError::ContestOptionActuallyInDifferentContest2 {
                        containing_contest_ix,
                        contestoption_contest_ix,
                    },
                });
            }
        }
        Ok(())
    }

    /// The effective selection limit for this [`ContestOption`].
    /// This is the smaller of this options's selection limit and the contest's selection limit.
    pub fn effective_selection_limit(
        &self,
        containing_contest: &Contest,
    ) -> EgResult<EffectiveOptionSelectionLimit> {
        self.validate_contest_ix_if_known(containing_contest)?;
        EffectiveOptionSelectionLimit::figure(containing_contest, self)
    }

    /// Validates the [`Option`] internally as much as practical. But since it doesn't have access
    /// to the other [`ContestOptions`] in the [`Contest`], it won't be able to check for
    /// duplicate [`ContestOption`] labels.
    pub fn validate(
        &self,
        containing_contest: &Contest,
        containing_contest_ix: ContestIndex,
        contest_option_ix: ContestOptionIndex,
    ) -> EgResult<()> {
        self.validate_contest_ix_if_known(containing_contest)?;

        // Validate the [`ContestOption`] Label.
        // EGDS 2.1.0 S3.1.3.b EGRI accepts ContestOption labels composed of printable characters and (internal, non-contiguous) 0x20 space characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels that contain line break characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels that have leading or trailing whitespace
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels that contain contiguous sequences of whitespace other than a single 0x20 space
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels that contain special characters (Unicode Category Cc, Cf, Zs, Zl, Zp, or Cs)
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels having no printable characters
        // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels that decode to a Unicode malformed surrogate pair (Unicode Category Cs). See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603)
        validate_label(
            self.label.as_str(),
            LabeledItem::ContestOption(containing_contest_ix, contest_option_ix),
        )?;

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
        election_manifest::{
            ElectionManifest, ElectionManifestInfo, t::common_test_election_manifest_jv,
        },
        loadable::{LoadableFromStdIoReadValidatable, LoadableFromStdIoReadValidated},
        serializable::{SerializableCanonical, SerializablePretty},
        validatable::{Validatable, Validated},
    };

    async fn common_test_contestoption_label(contestoption_label: &str) -> EgResult<()> {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(format!(
            "eg::election_manifest::t::test_contestoption_label: {contestoption_label:?}"
        ));
        let eg = eg.as_ref();

        let mut em_jv = common_test_election_manifest_jv(1);
        em_jv["contests"][0] = json!(
            { "label": "Some Contest", "options": [
                { "label": contestoption_label }
            ] });

        let em_js = serde_json::to_string_pretty(&em_jv).unwrap();

        let em_info = ElectionManifestInfo::from_json_str_validatable(em_js.as_str()).unwrap();

        ElectionManifest::try_validate_from(em_info, eg).map(|_| ())
    }

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            // EGDS 2.1.0 S3.1.3.b EGRI accepts ContestOption labels composed of printable characters and (internal, non-contiguous) 0x20 space characters
            assert_ron_snapshot!(common_test_contestoption_label(
                    "Thündéroak, Vâlêriana D. (Ëverbright)"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(common_test_contestoption_label(
                    "Stârførge, Cássánder A. (Møonfire)"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(common_test_contestoption_label(
                    "For"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(common_test_contestoption_label(
                    "Against"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(common_test_contestoption_label(
                    "Prō"
                ).await,
                @"Ok(())");
            assert_ron_snapshot!(common_test_contestoption_label(
                    "Ĉontrá"
                ).await,
                @"Ok(())");
        });
    }

    #[test_log::test]
    fn t2() {
        async_global_executor::block_on(async {
            // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels that contain line break characters
            assert_ron_snapshot!(common_test_contestoption_label(
                    "ContestOption\nlabel that contains a line break character"
                ).await,
                @r#"
            Err(LabelError(NotAllowedChar(CharNotAllowedInText(
              labeled_item: ContestOption(1, 1),
              char_ix1: 14,
              byte_offset: 13,
              unicode_property: Control,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels that have leading or trailing whitespace
            assert_ron_snapshot!(common_test_contestoption_label(
                    " ContestOption label that has leading whitespace"
                ).await,
                @r#"
            Err(LabelError(LeadingOrTrailingWhitespace((Leading, CharNotAllowedInText(
              labeled_item: ContestOption(1, 1),
              char_ix1: 1,
              byte_offset: 0,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            )))))"#);

            assert_ron_snapshot!(common_test_contestoption_label(
                    "ContestOption label that has trailing whitespace "
                ).await,
                @r#"
            Err(LabelError(LeadingOrTrailingWhitespace((Trailing, CharNotAllowedInText(
              labeled_item: ContestOption(1, 1),
              char_ix1: 49,
              byte_offset: 48,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            )))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels that contain contiguous sequences of whitespace other than a single 0x20 space
            assert_ron_snapshot!(common_test_contestoption_label(
                    "ContestOption  label that contains a contiguous sequences of whitespace"
                ).await,
                @r#"
            Err(LabelError(ContiguousWhitespace(CharNotAllowedInText(
              labeled_item: ContestOption(1, 1),
              char_ix1: 15,
              byte_offset: 14,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels that contain special characters (Unicode Category Cc, Cf, Zs, Zl, Zp, or Cs)
            // 0x002028 - LINE SEPARATOR - 'Zl'
            assert_ron_snapshot!(common_test_contestoption_label(
                    "ContestOption\u{002028}label that contains a special character"
                ).await,
                @r#"
            Err(LabelError(NotAllowedChar(CharNotAllowedInText(
              labeled_item: ContestOption(1, 1),
              char_ix1: 14,
              byte_offset: 13,
              unicode_property: LineSeparator,
              unicode_version: (16, 0, 0),
            ))))"#);

            // EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels having no printable characters
            assert_ron_snapshot!(common_test_contestoption_label(
                    ""
                ).await,
                @"Err(LabelError(NoPossiblyPrintableCharacters(ContestOption(1, 1))))");

            assert_ron_snapshot!(common_test_contestoption_label(
                    "\u{00200C}"
                ).await,
                @"Err(LabelError(NoPossiblyPrintableCharacters(ContestOption(1, 1))))");

            //? TODO EGDS 2.1.0 S3.1.3.b EGRI rejects ContestOption labels that decode to a Unicode malformed surrogate pair (Unicode Category Cs). See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603)
            //? TODO
        });
    }
}
