// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    ciphertext::{Ciphertext, CiphertextIndex},
    contest_option_fields::ContestOptionFieldsPlaintexts,
    election_manifest::ContestIndex,
    errors::{EgError, EgResult},
    pre_voting_data::PreVotingData,
    u31::Uint31,
    vec1::{HasIndexType, Vec1},
};

/// Value of a contest data field, which could be either a selectable option or additional data.
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

/// A `u32` can be made from a [`ContestDataFieldPlaintext`].
impl From<ContestDataFieldPlaintext> for u32 {
    fn from(cdfpt: ContestDataFieldPlaintext) -> Self {
        cdfpt.0.into()
    }
}

/// A `u64` can be made from a [`ContestDataFieldPlaintext`].
impl From<ContestDataFieldPlaintext> for u64 {
    fn from(cdfpt: ContestDataFieldPlaintext) -> Self {
        cdfpt.0.into()
    }
}

/// A `usize` can be made from a [`ContestDataFieldPlaintext`].
impl From<ContestDataFieldPlaintext> for usize {
    fn from(cdfpt: ContestDataFieldPlaintext) -> Self {
        static_assertions::const_assert!(31 <= usize::BITS);
        u32::from(cdfpt) as usize
    }
}

/// A [`BigUint`] can be made from a [`ContestDataFieldPlaintext`].
impl From<ContestDataFieldPlaintext> for BigUint {
    fn from(cdfpt: ContestDataFieldPlaintext) -> Self {
        BigUint::from(u32::from(cdfpt))
    }
}

/// A [`Vec1`] of [`ContestDataFieldPlaintext`] is indexed with the same type as [`Ciphertext`]
/// Same as [`ContestOption`], [`ContestOptionFieldPlaintext`], and possibly others.
impl HasIndexType for ContestDataFieldPlaintext {
    type IndexType = Ciphertext;
}

/// Same type as [`CiphertextIndex`], [`ContestOptionIndex`], [`ContestOptionFieldPlaintextIndex`], [`ContestDataFieldIndex`], etc.
pub type ContestDataFieldPlaintextIndex = CiphertextIndex;

/// Same type as [`CiphertextIndex`], [`ContestOptionIndex`], [`ContestOptionFieldPlaintextIndex`], [`ContestDataFieldPlaintextIndex`], etc.
pub type ContestDataFieldIndex = CiphertextIndex;

//-------------------------------------------------------------------------------------------------|

/// Values of the voter selectable options of a single contest.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContestDataFieldsPlaintexts(Vec1<ContestDataFieldPlaintext>);

impl ContestDataFieldsPlaintexts {
    /// - `contest_option_fields_plaintexts` should have the same length as the
    ///   number of options in the contest.
    pub fn try_from_option_fields(
        _pre_voting_data: &PreVotingData,
        _contest_ix: ContestIndex,
        option_fields_plaintexts: ContestOptionFieldsPlaintexts,
    ) -> EgResult<Self> {
        //? TODO: This is probably where we want to add additional data fields for under/overvote
        //? and enforce selection limit is satisfied

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
}

/// Access to the inner [`Vec1`] of [`ContestDataFieldsPlaintexts`].
impl AsRef<Vec1<ContestDataFieldPlaintext>> for ContestDataFieldsPlaintexts {
    fn as_ref(&self) -> &Vec1<ContestDataFieldPlaintext> {
        &self.0
    }
}
