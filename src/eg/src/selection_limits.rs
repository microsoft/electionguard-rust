// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use serde::{Deserialize, Serialize};
use util::vec1::HasIndexType;

use crate::{
    ciphertext::{Ciphertext, CiphertextIndex},
    contest::Contest,
    contest_option::ContestOption,
    eg::Eg,
    errors::{EgError, EgResult},
};

//=================================================================================================|

/// The maximum number of selections ("votes") that may be distributed over all the selectable
/// options of a contest.
///
/// For compatibility with other "small" integers used in ElectionGuard, the largest
/// value is [`i32::MAX`] or `2,147,483,647`.
#[derive(
    Debug,
    derive_more::Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    PartialOrd,
    Ord
)]
pub struct ContestSelectionLimit(pub u32);

//? TODO make enum with 'NoLimit' variant

impl ContestSelectionLimit {
    /// The largest possible contest selection limit as `u32`, equal to
    /// [`i32::MAX`] or `2,147,483,647`.
    pub const LIMIT_MAX_U32: u32 = i32::MAX as u32;

    /// Returns `true` if the contest selection limit is the default value of `1`.
    pub fn is_default(&self) -> bool {
        *self == ContestSelectionLimit::default()
    }
}

impl Default for ContestSelectionLimit {
    /// The default contest selection limit is [`Limit`](ContestSelectionLimit::Limit)(1).
    fn default() -> Self {
        ContestSelectionLimit(1)
    }
}

impl From<ContestSelectionLimit> for u32 {
    fn from(contest_selection_limit: ContestSelectionLimit) -> Self {
        contest_selection_limit.0
    }
}

/// A `usize` can be made from a [`ContestSelectionLimit`].
impl From<ContestSelectionLimit> for usize {
    fn from(contest_selection_limit: ContestSelectionLimit) -> Self {
        static_assertions::const_assert!(31 <= usize::BITS);
        contest_selection_limit.0 as usize
    }
}

/// A `u64` can be made from a [`ContestSelectionLimit`].
impl From<ContestSelectionLimit> for u64 {
    fn from(contest_selection_limit: ContestSelectionLimit) -> Self {
        contest_selection_limit.0 as u64
    }
}

/// Any `u8` value can be a contest selection limit.
impl From<u8> for ContestSelectionLimit {
    fn from(n: u8) -> Self {
        ContestSelectionLimit(n as u32)
    }
}

/// Any `u16` value can be a contest selection limit.
impl From<u16> for ContestSelectionLimit {
    fn from(n: u16) -> Self {
        ContestSelectionLimit(n as u32)
    }
}

impl TryFrom<u32> for ContestSelectionLimit {
    type Error = EgError;
    fn try_from(n: u32) -> EgResult<Self> {
        match n {
            0..=Self::LIMIT_MAX_U32 => Ok(ContestSelectionLimit(n)),
            _ => Err(EgError::ContestSelectionLimitOutOfSupportedRange(n as u64)),
        }
    }
}

//-------------------------------------------------------------------------------------------------|

/// The maximum number of selections ("votes") that may be applied to a specific contest option.
///
/// For compatibility with other "small" integers used in ElectionGuard, the largest finite
/// value is [`i32::MAX`] or `2,147,483,647`.
///
/// Note that the effective option selection limit will be the smaller of the contest selection
/// limit and any specified option limit. Also, the sum of all applied selections must not
/// exceed the contest selection limit. However, enforcing that constraint is outside the scope
/// of this type.
#[derive(
    Debug,
    derive_more::Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord
)]
pub enum OptionSelectionLimit {
    /// An option selection limit is specified.
    Limit(u32), //? TODO u31 instead

    /// No option selection limit is specified, only the contest selection limit applies.
    LimitedOnlyByContest,
}

use serde::ser::Serializer;

impl Serialize for OptionSelectionLimit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use OptionSelectionLimit::*;
        match self {
            Limit(n) => serializer.serialize_u32(*n),
            LimitedOnlyByContest => serializer.serialize_str("CONTEST_LIMIT"),
        }
    }
}

impl<'de> Deserialize<'de> for OptionSelectionLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct OptionSelectionLimitVisitor;

        impl de::Visitor<'_> for OptionSelectionLimitVisitor {
            type Value = OptionSelectionLimit;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("An integer in the supported range of 0 to 2147483647, or the string \"CONTEST_LIMIT\"")
            }

            fn visit_str<E>(self, value: &str) -> Result<OptionSelectionLimit, E>
            where
                E: de::Error,
            {
                match value {
                    "CONTEST_LIMIT" => Ok(OptionSelectionLimit::LimitedOnlyByContest),
                    _ => Err(de::Error::unknown_variant(value, &["\"CONTEST_LIMIT\""])),
                }
            }

            fn visit_u64<E>(self, value: u64) -> Result<OptionSelectionLimit, E>
            where
                E: de::Error,
            {
                OptionSelectionLimit::try_from(value).map_err(|_| {
                    de::Error::invalid_value(
                        serde::de::Unexpected::Unsigned(value),
                        &"An integer in the supported range of 0 to 2147483647",
                    )
                })
            }
        }

        deserializer.deserialize_any(OptionSelectionLimitVisitor)
    }
}

impl OptionSelectionLimit {
    /// The largest actualy-limiting option selection limit as `u32`.
    pub const LIMIT_MAX_U32: u32 = i32::MAX as u32;

    /// The largest actualy-limiting option selection limit as `u64`.
    pub const LIMIT_MAX_U64: u64 = Self::LIMIT_MAX_U32 as u64;

    /// Returns `true` if the option selection limit is the default value of
    /// [`Limit(1)`](`OptionSelectionLimit::Limit`).
    pub fn is_default(&self) -> bool {
        *self == OptionSelectionLimit::default()
    }

    /// If the option selection limit is [`Limit(n)`](OptionSelectionLimit::Limit), returns
    /// the limit as a `u32`. Returns [`None`] if it's
    /// [`LimitedOnlyByContest`](`OptionSelectionLimit::LimitedOnlyByContest`).
    pub fn limit_u32(self) -> Option<u32> {
        self.try_into().ok()
    }
}

impl Default for OptionSelectionLimit {
    /// The default option selection limit is [`Limit(1)`](OptionSelectionLimit::Limit).
    fn default() -> Self {
        OptionSelectionLimit::Limit(1)
    }
}

/// Any `u8` value can be an option selection limit.
impl From<u8> for OptionSelectionLimit {
    fn from(n: u8) -> Self {
        OptionSelectionLimit::Limit(n as u32)
    }
}

/// Any `u16` value can be an option selection limit.
impl From<u16> for OptionSelectionLimit {
    fn from(n: u16) -> Self {
        OptionSelectionLimit::Limit(n as u32)
    }
}

/// Any `u32` value less than or equal to [`OptionSelectionLimit::LIMIT_MAX_U32`]
/// can be an [`OptionSelectionLimit`].
impl TryFrom<u32> for OptionSelectionLimit {
    type Error = EgError;
    fn try_from(n: u32) -> EgResult<Self> {
        match n {
            0..=Self::LIMIT_MAX_U32 => Ok(OptionSelectionLimit::Limit(n)),
            _ => Err(EgError::OptionSelectionLimitOutOfSupportedRange(n as u64)),
        }
    }
}

/// Any `u64` value less than or equal to [`OptionSelectionLimit::LIMIT_MAX_U32`]
/// can be an [`OptionSelectionLimit`].
impl TryFrom<u64> for OptionSelectionLimit {
    type Error = EgError;
    fn try_from(n: u64) -> EgResult<Self> {
        match n {
            0..=Self::LIMIT_MAX_U64 => Ok(OptionSelectionLimit::Limit(n as u32)),
            _ => Err(EgError::OptionSelectionLimitOutOfSupportedRange(n)),
        }
    }
}

/// An [`OptionSelectionLimit::Limit`] may be converted to `u32`,
/// but not [`OptionSelectionLimit::LimitedOnlyByContest`] variant.
impl TryFrom<OptionSelectionLimit> for u32 {
    type Error = EgError;

    /// Converts the option selection limit to `u32` if it is
    /// [`Limit(n)`](OptionSelectionLimit::Limit).
    /// Otherwise, returns an error.
    fn try_from(option_selection_limit: OptionSelectionLimit) -> EgResult<u32> {
        use OptionSelectionLimit::*;
        match option_selection_limit {
            Limit(n) => Ok(n),
            LimitedOnlyByContest => Err(EgError::OptionSelectionLimitIsNotNumeric),
        }
    }
}

impl std::ops::Add for OptionSelectionLimit {
    type Output = Self;

    /// Adds two option selection limits. Addition (among two `Limit` values) quietly saturates at
    /// `LIMIT_MAX_U32`, since that is the largest value that can be possible for a
    /// `ContestSelectionLimit` anyway.
    #[inline]
    fn add(self, other: Self) -> Self {
        use OptionSelectionLimit::*;
        match (self, other) {
            (Limit(lhs), Limit(rhs)) => Limit(Self::LIMIT_MAX_U32.min(lhs + rhs)),
            _ => LimitedOnlyByContest,
        }
    }
}

impl std::iter::Sum<Self> for OptionSelectionLimit {
    #[inline]
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(OptionSelectionLimit::Limit(0), |acc, rhs| acc + rhs)
    }
}

//-------------------------------------------------------------------------------------------------|

/// The effective selection limit for a contest is the smaller of this contest's selection limit
/// and the sum of the options' selection limits.
#[derive(
    Debug,
    derive_more::Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord
)]
pub struct EffectiveContestSelectionLimit(u32);

impl EffectiveContestSelectionLimit {
    pub fn figure(contest: &Contest) -> EgResult<EffectiveContestSelectionLimit> {
        let csl = contest.selection_limit.into();

        let osl_sum: OptionSelectionLimit = contest
            .contest_options
            .iter()
            .map(|o| o.selection_limit)
            .sum();

        use OptionSelectionLimit::*;
        let ecsl = match osl_sum {
            Limit(o_limit) => o_limit.min(csl),
            LimitedOnlyByContest => csl,
        };

        Ok(EffectiveContestSelectionLimit(ecsl))
    }
}

impl From<EffectiveContestSelectionLimit> for u32 {
    fn from(effective_contest_selection_limit: EffectiveContestSelectionLimit) -> Self {
        effective_contest_selection_limit.0
    }
}

//-------------------------------------------------------------------------------------------------|

/// A 1-based index of a [`EffectiveOptionSelectionLimit`] in the order it is defined within its
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
pub type EffectiveOptionSelectionLimitIndex = CiphertextIndex;

impl HasIndexType for EffectiveOptionSelectionLimit {
    type IndexTypeParam = Ciphertext;
}

/// The effective selection limit for an option is the smaller of the options's selection limit
/// and its contest's selection limit.
#[derive(
    Debug,
    derive_more::Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord
)]
pub struct EffectiveOptionSelectionLimit(pub u32);

impl EffectiveOptionSelectionLimit {
    pub fn figure(
        contest: &Contest,
        contest_option: &ContestOption,
    ) -> EgResult<EffectiveOptionSelectionLimit> {
        let csl = contest.selection_limit.into();

        use OptionSelectionLimit::*;
        let eosl = match contest_option.selection_limit {
            Limit(o_limit) => o_limit.min(csl),
            LimitedOnlyByContest => csl,
        };

        Ok(EffectiveOptionSelectionLimit(eosl))
    }
}

impl From<EffectiveOptionSelectionLimit> for u32 {
    fn from(eosl: EffectiveOptionSelectionLimit) -> Self {
        eosl.0
    }
}

/// A `usize` can be made from a [`EffectiveOptionSelectionLimit`].
impl From<EffectiveOptionSelectionLimit> for usize {
    fn from(eosl: EffectiveOptionSelectionLimit) -> Self {
        static_assertions::const_assert!(u32::BITS <= usize::BITS);
        eosl.0 as usize
    }
}

impl From<EffectiveOptionSelectionLimit> for u64 {
    fn from(eosl: EffectiveOptionSelectionLimit) -> Self {
        eosl.0 as u64
    }
}
