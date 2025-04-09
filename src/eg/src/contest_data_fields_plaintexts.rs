// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::option;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
use util::{
    uint31::Uint31,
    vec1::{HasIndexType, Vec1},
};

use crate::{
    ballot_style::BallotStyle,
    ciphertext::{Ciphertext, CiphertextIndex},
    contest_option_fields::ContestOptionFieldsPlaintexts,
    eg::Eg,
    election_manifest::{ContestIndex, ElectionManifest},
    errors::{EgError, EgResult},
    pre_voting_data::PreVotingData,
    resource::{ProduceResource, ProduceResourceExt},
};

/// Value (plaintext) of a contest data fields, which could be a selectable option or additional data.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ContestDataFieldPlaintext(Uint31);

impl ContestDataFieldPlaintext {
    /// A [`ContestDataFieldPlaintext`] can be made from any type that can be converted into a
    /// [`Uint31`].
    pub fn new<T: Into<Uint31>>(t: T) -> Self {
        Self(t.into())
    }

    /// A [`ContestDataFieldPlaintext`] can be made from any type that can be converted into a
    /// [`Uint31`].
    pub fn try_new<T>(t: T) -> EgResult<Self>
    where
        T: TryInto<Uint31>,
        <T as TryInto<Uint31>>::Error: Into<EgError>,
    {
        TryInto::<Uint31>::try_into(t).map_err(Into::into).map(Self)
    }
}

impl From<ContestDataFieldPlaintext> for u32 {
    /// A [`u32`] can always be made from a [`ContestDataFieldPlaintext`].
    #[inline]
    fn from(src: ContestDataFieldPlaintext) -> Self {
        src.0.into()
    }
}

impl From<ContestDataFieldPlaintext> for u64 {
    /// A [`u64`] can always be made from a [`ContestDataFieldPlaintext`].
    #[inline]
    fn from(src: ContestDataFieldPlaintext) -> Self {
        src.0.into()
    }
}

impl From<ContestDataFieldPlaintext> for usize {
    /// A [`usize`] can always be made from a [`ContestDataFieldPlaintext`].
    #[inline]
    fn from(src: ContestDataFieldPlaintext) -> Self {
        static_assertions::const_assert!(31 <= usize::BITS);
        u32::from(src) as usize
    }
}

/// A [`BigUint`] can be made from a [`ContestDataFieldPlaintext`].
impl From<ContestDataFieldPlaintext> for BigUint {
    fn from(cdfpt: ContestDataFieldPlaintext) -> Self {
        BigUint::from(u32::from(cdfpt))
    }
}

impl HasIndexType for ContestDataFieldPlaintext {
    type IndexTypeParam = Ciphertext;
}

/// Same type as [`CiphertextIndex`], [`ContestOptionIndex`](crate::election_manifest::ContestOptionIndex), [`ContestOptionFieldPlaintextIndex`](crate::contest_option_fields::ContestOptionFieldPlaintextIndex), [`ContestDataFieldIndex`], etc.
pub type ContestDataFieldIndex = CiphertextIndex;

//-------------------------------------------------------------------------------------------------|

/// Values (plaintext) of the data fields, which could be a selectable option or additional data, of a single contest.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContestDataFieldsPlaintexts(Vec1<ContestDataFieldPlaintext>);

impl ContestDataFieldsPlaintexts {
    /// Produces a [`ContestDataFieldsPlaintexts`] from a [`ContestOptionFieldsPlaintexts`].
    ///
    /// - `election_manifest` - The [`ElectionManifest`].
    /// - `contest_ix` - The Contest Index
    /// - `option_fields_plaintexts` - The list of values representing voter selections. Its length must
    ///   be equal to the number of [`ContestOption`](crate::election_manifest::ContestOption)s defined for
    ///   the [`Contest`](crate::election_manifest::Contest). This value is returned by the
    ///   [`Contest::qty_contest_option_data_fields()`](crate::election_manifest::Contest::qty_contest_option_data_fields)
    ///   function.
    pub fn try_from_option_fields(
        election_manifest: &ElectionManifest,
        ballot_style: &BallotStyle,
        contest_ix: ContestIndex,
        option_fields_plaintexts: ContestOptionFieldsPlaintexts,
    ) -> EgResult<Self> {
        let contest = ballot_style.get_contest(election_manifest, contest_ix)?;
        let qty_contest_option_data_fields = contest.qty_contest_option_data_fields();

        if option_fields_plaintexts.len() != qty_contest_option_data_fields + 1 {
            let e = EgError::IncorrectQtyOfContestOptionFieldsPlaintexts {
                contest_ix,
                qty_expected: qty_contest_option_data_fields,
                qty_supplied: option_fields_plaintexts.len(),
            };
            error!("{e}");
            return Err(e);
        }

        //? TODO: This is probably where we want to add system-assigned data fields for recording (under|over)vote(ed|amount)
        //? TODO: Enforce selection limit
        //? TODO: Include additional data fields

        let v1_option_fields_plaintexts = option_fields_plaintexts.into_inner();

        let mut v1 =
            Vec1::<ContestDataFieldPlaintext>::with_capacity(v1_option_fields_plaintexts.len());
        for (_option_field_ix, &option_field_plaintext) in v1_option_fields_plaintexts.enumerate() {
            let data_field_plaintext = ContestDataFieldPlaintext::new(option_field_plaintext);
            v1.try_push(data_field_plaintext)?;
        }
        Ok(Self(v1))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[ContestDataFieldPlaintext] {
        self.0.as_slice()
    }

    #[allow(non_snake_case)]
    pub fn as_Vec1_ContestDataFieldPlaintext(&self) -> &Vec1<ContestDataFieldPlaintext> {
        &self.0
    }

    /// Gets the [`ContestDataFieldPlaintext`] at the specified index, if present.
    pub fn get(
        &self,
        contest_data_field_ix: ContestDataFieldIndex,
    ) -> Option<ContestDataFieldPlaintext> {
        self.as_Vec1_ContestDataFieldPlaintext()
            .get(contest_data_field_ix)
            .copied()
    }
}
