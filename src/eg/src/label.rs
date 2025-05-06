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
use unicode_properties::UnicodeGeneralCategory;

//
use util::index::Index;

use crate::{
    ballot_style::BallotStyleIndex, contest::ContestIndex, contest_option::ContestOptionIndex,
    guardian::GuardianIndex,
};

//=================================================================================================|

/// When we need to refer to an item with a `Label`, e.g., in [`LabelError`].
///
/// [`Label`](doc/specs/ElectionGuard_2.1.0_Serialization_Specification.html#Label).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(serde::Deserialize, serde::Serialize)]
#[derive(strum::Display)]
pub enum LabeledItem {
    Guardian(GuardianIndex),
    ElectionManifest,
    Contest(ContestIndex),
    ContestOption(ContestIndex, ContestOptionIndex),
    BallotStyle(Option<BallotStyleIndex>),
}

//=================================================================================================|

/// [Unicode Character Category](https://www.unicode.org/notes/tn36/) of characters that may be not
/// allowed in a Label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(serde::Deserialize, serde::Serialize)]
#[derive(strum::AsRefStr, strum::Display, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum UnicodeProperty {
    /// Whitespace (blank text) as defined by [`std::primitive::char::is_whitespace()`]
    #[strum(to_string = "Whitespace - blank space")]
    Whitespace,

    #[strum(to_string = "Cc - C0 or C1 control code")]
    Control,

    #[strum(to_string = "Cf - Format control character")]
    Format,

    #[strum(to_string = "Zs - Various non-zero width space characters")]
    SpaceSeparator,

    #[strum(to_string = "Zl - U+2028 LINE SEPARATOR")]
    LineSeparator,

    #[strum(to_string = "Zp - U+2029 PARAGRAPH SEPARATOR")]
    ParagraphSeparator,

    #[strum(to_string = "Cs - Surrogate code point")]
    Surrogate,

    #[strum(to_string = "Noncharacters")]
    Noncharacter,
    // #[strum(to_string = "Co - Private use")]
    // PrivateUse,

    // #[strum(to_string = "Cn - Unassigned, reserved")]
    // Unassigned,
    CodePointOutOfRange,
}

//=================================================================================================|
static UNICODE_PROPERTIES_UNICODE_VERSION_ARR: [u64; 3] = {
    let uv = unicode_properties::UNICODE_VERSION;
    [uv.0, uv.1, uv.2]
};

static STD_CHAR_UNICODE_VERSION_ARR: [u64; 3] = {
    let uv = std::char::UNICODE_VERSION;
    [uv.0 as u64, uv.1 as u64, uv.2 as u64]
};

//=================================================================================================|

/// Information common to errors in which a text field contains a not allowed character.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(serde::Deserialize, serde::Serialize)]
pub struct CharNotAllowedInText {
    labeled_item: LabeledItem,
    char_ix1: Index<char>,
    byte_offset: usize,
    unicode_property: UnicodeProperty,
    unicode_version: [u64; 3],
}

impl CharNotAllowedInText {
    pub fn new_unicode_properties_crate(
        labeled_item: LabeledItem,
        char_ix1: Index<char>,
        byte_offset: usize,
        unicode_category: UnicodeProperty,
    ) -> Self {
        Self {
            labeled_item,
            char_ix1,
            byte_offset,
            unicode_property: unicode_category,
            unicode_version: UNICODE_PROPERTIES_UNICODE_VERSION_ARR,
        }
    }
}

//=================================================================================================|

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(serde::Deserialize, serde::Serialize)]
#[derive(strum::Display)]
pub enum LeadingTrailing {
    Leading,
    Trailing,
}

/// [`Result::Err`](std::result::Result) type of a data resource production operation.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum EgLabelError {
    #[error(
"Character at (1-based) char position `{char_ix1}` (0-based byte offset `{byte_offset}`)\
 is of Unicode category `{unicode_category}`, which is not allowed in a `{labeled_item}` Label.",
        labeled_item = _0.labeled_item,
        char_ix1 = _0.char_ix1,
        byte_offset = _0.byte_offset,
        unicode_category = _0.unicode_property,
        //uv_maj = _0.unicode_version[0],
        //uv_min = _0.unicode_version[1],
        //uv_rev = _0.unicode_version[2],
    )]
    NotAllowedChar(CharNotAllowedInText),

    #[error(
"Character at (1-based) char position `{char_ix1}` (0-based byte offset `{byte_offset}`)\
 is the second of multiple contiguous whitespace (blank text) characters, which are not allowed \
 in a `{labeled_item}` Label.",
        labeled_item = _0.labeled_item,
        char_ix1 = _0.char_ix1,
        byte_offset = _0.byte_offset,
    )]
    ContiguousWhitespace(CharNotAllowedInText),

    #[error("{leading_trailing} whitespace (blank text) is not allowed in a `{labeled_item}` Label,\
 at (1-based) char position `{char_ix1}` (0-based byte offset `{byte_offset}`).",
        leading_trailing = _0.0,
        labeled_item = _0.1.labeled_item,
        char_ix1 = _0.1.char_ix1,
        byte_offset = _0.1.byte_offset,
    )]
    LeadingOrTrailingWhitespace((LeadingTrailing, CharNotAllowedInText)),

    #[error("The `{labeled_item}` Label has no printable characters.", labeled_item = _0)]
    NoPossiblyPrintableCharacters(LabeledItem),
}

//=================================================================================================|

/// Validates that a `Label` conforms to the rules given on EGDS 2.1.0 Sec. 3.1.3 pg. 16.
#[rustfmt::skip]
pub fn validate_label(s: &str, labeled_item: LabeledItem) -> Result<(), EgLabelError> {
    // EGDS 2.1.0 S3.1.3.b EGRI rejects [...] labels that contain line break characters, tabs, or similar special characters

    // Saturating a character index value to ~2 GiB seems justified for an error message.
    fn ix0_to_ix1(ix0: usize)->Index<char> {
        Index::from_zero_based_index_saturating_use_with_care(ix0)
    }

    let mut is_whitespace = false;
    let mut is_whitespace_prev = false;
    let mut cnt_possibly_printable = 0_usize;
    let mut char_ix0 = 0_usize;
    let mut byte_offset_prev = 0_usize;

    let mut char_indices = s.char_indices();
    loop {
        let byte_offset = char_indices.offset(); // Have to record this before the call to char_indices.next()

        let Some(pr) = char_indices.next() else {
            break;
        };
        char_ix0 = pr.0;
        let ch = pr.1;

        is_whitespace = ch.is_whitespace();

        if is_whitespace {
            if char_ix0 == 0 {
                let e = EgLabelError::LeadingOrTrailingWhitespace((
                    LeadingTrailing::Leading,
                    CharNotAllowedInText {
                        labeled_item,
                        char_ix1: ix0_to_ix1(char_ix0),
                        byte_offset,
                        unicode_property: UnicodeProperty::Whitespace,
                        unicode_version: STD_CHAR_UNICODE_VERSION_ARR,
                    } ));
                trace!("{e}");
                return Err(e);
            } else if is_whitespace_prev {
                let e = EgLabelError::ContiguousWhitespace(
                    CharNotAllowedInText {
                        labeled_item,
                        char_ix1: ix0_to_ix1(char_ix0),
                        byte_offset,
                        unicode_property: UnicodeProperty::Whitespace,
                        unicode_version: STD_CHAR_UNICODE_VERSION_ARR,
                    } );
                trace!("{e}");
                return Err(e);
            }
        }

        let code_point_u32 = ch as u32;

        match code_point_u32 {
            0x000020 => { }  // ASCII space 0x20 allowed, but not considered printable.
            _ => {
                use unicode_properties::GeneralCategory as UPGC;
                use unicode_properties::GeneralCategoryGroup as UPGCG;

                let opt_not_allowed_unicode_property: Option::<UnicodeProperty> =
                    (0x10FFFF < code_point_u32).then_some(UnicodeProperty::CodePointOutOfRange)
                    .or_else(|| (
                                (0x00FDD0..=0x00FDEF).contains(&code_point_u32)
                            || code_point_u32 == 0x00FEFF
                            || (code_point_u32 & 0x00FFFE) == 0x00FFFE
                        ).then_some(UnicodeProperty::Noncharacter))
                    .or_else(|| {
                        let upgc = ch.general_category();
                        let upgcg = ch.general_category_group();

                        match (upgcg, upgc) {
                            // Category 'Format' 'Cf' is allowed, but not considered printable.
                            ( _,          UPGC::Format)             => None,

                            // These categories are not allowed.
                            ( _,          UPGC::Control)            => Some(UnicodeProperty::Control),
                            ( _,          UPGC::SpaceSeparator)     => Some(UnicodeProperty::SpaceSeparator),
                            ( _,          UPGC::LineSeparator)      => Some(UnicodeProperty::LineSeparator),
                            ( _,          UPGC::ParagraphSeparator) => Some(UnicodeProperty::ParagraphSeparator),
                            ( _,          UPGC::Surrogate)          => Some(UnicodeProperty::Surrogate),

                            // Basically everything else is allowed and considered possibly printable
                            (   UPGCG::Letter,      _                )
                            | ( UPGCG::Mark,        _                )
                            | ( UPGCG::Number,      _                )
                            | ( UPGCG::Punctuation, _                )
                            | ( UPGCG::Symbol,      _                )
                            | ( _,                  UPGC::PrivateUse )
                            | ( _,                  UPGC::Unassigned )
                            | ( _,                  _                )
                            => {
                                cnt_possibly_printable += 1;
                                None
                            }
                        }
                    });

                if let Some(unicode_property) = opt_not_allowed_unicode_property {
                    let cnait = CharNotAllowedInText {
                        labeled_item,
                        char_ix1: ix0_to_ix1(char_ix0),
                        byte_offset,
                        unicode_property,
                        unicode_version: UNICODE_PROPERTIES_UNICODE_VERSION_ARR,
                    };
                    let e = EgLabelError::NotAllowedChar(cnait);
                    trace!("{e}");
                    return Err(e);
                }
            }
        }

        byte_offset_prev = byte_offset;
        is_whitespace_prev = is_whitespace;
    }

    if is_whitespace {
        let e = EgLabelError::LeadingOrTrailingWhitespace((
            LeadingTrailing::Trailing,
            CharNotAllowedInText {
                labeled_item,
                char_ix1: ix0_to_ix1(char_ix0),
                byte_offset: byte_offset_prev,
                unicode_property: UnicodeProperty::Whitespace,
                unicode_version: STD_CHAR_UNICODE_VERSION_ARR,
            } ));
        trace!("{e}");
        return Err(e);
    }

    if cnt_possibly_printable == 0 {
        let e = EgLabelError::NoPossiblyPrintableCharacters(labeled_item);
        trace!("{e}");
        return Err(e);
    }

    Ok(())
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use insta::assert_ron_snapshot;

    fn v(label: &str) -> Result<(), EgLabelError> {
        match validate_label(label, LabeledItem::ElectionManifest) {
            Err(EgLabelError::NotAllowedChar(cnait)) => {
                // Hard-code the Unicode version so crate updates don't break the tests needlessly.
                let cnait = CharNotAllowedInText {
                    unicode_version: [16, 0, 0],
                    ..cnait
                };
                Err(EgLabelError::NotAllowedChar(cnait))
            }
            result => result,
        }
    }

    #[test]
    fn t1() {
        // EGDS 2.1.0 S3.1.3.b accepts [...] labels composed of printable characters and (internal, non-contiguous) 0x20 space characters"

        assert_ron_snapshot!(v("Silvërspîre County Register of Deeds Sébastian Moonglôw to be retained"), @"Ok(())");
        assert_ron_snapshot!(v("Gávrïel Runëbørne (Stärsky)"), @"Ok(())");
        assert_ron_snapshot!(v("Prō"), @"Ok(())");
        assert_ron_snapshot!(v("!"), @"Ok(())");
    }

    #[test]
    fn t2() {
        // EGDS 2.1.0 S3.1.3.b EGRI rejects [...] labels that contain line break characters"
        assert_ron_snapshot!(v("line\nbreak"), @r#"
        Err(NotAllowedChar(CharNotAllowedInText(
          labeled_item: ElectionManifest,
          char_ix1: 5,
          byte_offset: 4,
          unicode_property: Control,
          unicode_version: (16, 0, 0),
        )))"#);
    }

    #[test]
    fn t3() {
        // EGDS 2.1.0 S3.1.3.b EGRI rejects [...] labels that have leading or trailing whitespace

        assert_ron_snapshot!(v(" Retain"), @r#"
        Err(LeadingOrTrailingWhitespace((Leading, CharNotAllowedInText(
          labeled_item: ElectionManifest,
          char_ix1: 1,
          byte_offset: 0,
          unicode_property: Whitespace,
          unicode_version: (16, 0, 0),
        ))))
        "#);

        assert_ron_snapshot!(v("Remove "), @r#"
        Err(LeadingOrTrailingWhitespace((Trailing, CharNotAllowedInText(
          labeled_item: ElectionManifest,
          char_ix1: 7,
          byte_offset: 6,
          unicode_property: Whitespace,
          unicode_version: (16, 0, 0),
        ))))
        "#);
    }

    #[test]
    fn t4() {
        // EGDS 2.1.0 S3.1.3.b EGRI rejects [...] labels that contain contiguous sequences of whitespace other than a single 0x20 space

        assert_ron_snapshot!(v("abcd  efgh"), @r#"
        Err(ContiguousWhitespace(CharNotAllowedInText(
          labeled_item: ElectionManifest,
          char_ix1: 6,
          byte_offset: 5,
          unicode_property: Whitespace,
          unicode_version: (16, 0, 0),
        )))
        "#);

        assert_ron_snapshot!(v("abcd \tefgh"), @r#"
        Err(ContiguousWhitespace(CharNotAllowedInText(
          labeled_item: ElectionManifest,
          char_ix1: 6,
          byte_offset: 5,
          unicode_property: Whitespace,
          unicode_version: (16, 0, 0),
        )))
        "#);
    }

    #[test]
    fn t5() {
        // EGDS 2.1.0 S3.1.3.b EGRI rejects [...] labels that contain special characters (Unicode Category Cc, Cf, Zs, Zl, Zp, or Cs)

        // 0085          ; White_Space # Cc       <control-0085>
        assert_ron_snapshot!(v("a\u{000085}b"), @r#"
        Err(NotAllowedChar(CharNotAllowedInText(
          labeled_item: ElectionManifest,
          char_ix1: 2,
          byte_offset: 1,
          unicode_property: Control,
          unicode_version: (16, 0, 0),
        )))"#);

        // 061C ; Bidi_Control   # Cf       ARABIC LETTER MARK
        assert_ron_snapshot!(v("a\u{00061C}b"), @"Ok(())");

        // 0x002028 - LINE SEPARATOR - 'Zl'
        assert_ron_snapshot!(v("a\u{002028}b"), @r#"
        Err(NotAllowedChar(CharNotAllowedInText(
          labeled_item: ElectionManifest,
          char_ix1: 2,
          byte_offset: 1,
          unicode_property: LineSeparator,
          unicode_version: (16, 0, 0),
        )))"#);

        // 2029 ; Pattern_White_Space    # Zp       PARAGRAPH SEPARATOR
        assert_ron_snapshot!(v("a\u{002029}b"), @r#"
        Err(NotAllowedChar(CharNotAllowedInText(
          labeled_item: ElectionManifest,
          char_ix1: 2,
          byte_offset: 1,
          unicode_property: ParagraphSeparator,
          unicode_version: (16, 0, 0),
        )))"#);
    }

    #[test]
    fn t6() {
        // EGDS 2.1.0 S3.1.3.b EGRI rejects [...] labels having no printable characters
        assert_ron_snapshot!(v(""), @"Err(NoPossiblyPrintableCharacters(ElectionManifest))");
        assert_ron_snapshot!(v("\u{00200C}"), @"Err(NoPossiblyPrintableCharacters(ElectionManifest))");
    }

    /* //? TODO
    #[test]
    fn t7() {
        //? TODO EGDS 2.1.0 S3.1.3.b EGRI rejects [...] labels that decode to a Unicode malformed surrogate pair (Unicode Category Cs). See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603)

        // 0xD800-DBFF is the first half of a surrogate pair.
        // 0xDC00-DFFF is the second half of a surrogate pair.

        // Example `U+24B62` from Wikipedia https://en.wikipedia.org/wiki/UTF-16
        //assert_ron_snapshot!(v(b"\u{00D852}\u{00DF62}"), @"");

        //assert_ron_snapshot!(v("\u{00D800}"), @"Err(NoPossiblyPrintableCharacters(ContestOption))");
        //assert_ron_snapshot!(v("\u{00D800}"), @"Err(NoPossiblyPrintableCharacters(ContestOption))");
    }
    // */
}
