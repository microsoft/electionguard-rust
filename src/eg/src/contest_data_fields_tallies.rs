// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use serde::{Deserialize, Serialize};
use util::{
    uint53::{Uint53, Uint53Error},
    vec1::{HasIndexType, Vec1},
};

use crate::{
    ciphertext::{Ciphertext, CiphertextIndex},
    eg::Eg,
    election_manifest::{Contest, ElectionManifest},
    errors::EgResult,
};

/// Plaintext value of a tally of a contest data field, which could represent either a selectable option or additional data.
///
/// Note that in many cases you would instead use 'ContestDataFieldsCiphertexts' and 'ContestDataFieldsVerifiableDecryptions',
/// as those will allow verification of both the [`ContestSelectionLimit`] and individual [`ContestDataFieldLimit`].
///
//? TODO maybe this goes away entirely?
#[derive(
    Debug,
    derive_more::Deref,
    derive_more::DerefMut,
    derive_more::Display,
    Clone,
    Copy,
    Serialize,
    Deserialize
)]
#[serde(transparent)]
pub struct ContestDataFieldTally(Uint53);

impl ContestDataFieldTally {
    pub fn zero() -> ContestDataFieldTally {
        ContestDataFieldTally(Uint53::zero())
    }
}

impl From<u8> for ContestDataFieldTally {
    /// A [`ContestDataFieldTally`] can always be made from a [`u8`].
    #[inline]
    fn from(value: u8) -> Self {
        ContestDataFieldTally(value.into())
    }
}

impl TryFrom<i8> for ContestDataFieldTally {
    type Error = Uint53Error;
    /// One can try to make a [`ContestDataFieldTally`] from an [`i8`].
    #[inline]
    fn try_from(value: i8) -> Result<Self, Self::Error> {
        Ok(ContestDataFieldTally(value.try_into()?))
    }
}

impl From<u16> for ContestDataFieldTally {
    /// A [`ContestDataFieldTally`] can always be made from a [`u16`].
    #[inline]
    fn from(value: u16) -> Self {
        ContestDataFieldTally(value.into())
    }
}

impl TryFrom<i16> for ContestDataFieldTally {
    type Error = Uint53Error;
    /// One can try to make a [`ContestDataFieldTally`] from an [`i16`].
    #[inline]
    fn try_from(value: i16) -> Result<Self, Self::Error> {
        Ok(ContestDataFieldTally(value.try_into()?))
    }
}

impl From<u32> for ContestDataFieldTally {
    /// A [`ContestDataFieldTally`] can always be made from a [`u32`].
    #[inline]
    fn from(value: u32) -> Self {
        ContestDataFieldTally(value.into())
    }
}

impl TryFrom<i32> for ContestDataFieldTally {
    type Error = Uint53Error;
    /// One can try to make a [`ContestDataFieldTally`] from an [`i32`].
    #[inline]
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(ContestDataFieldTally(value.try_into()?))
    }
}

impl From<Uint53> for ContestDataFieldTally {
    /// A [`ContestDataFieldTally`] can always be made from a [`Uint53`].
    #[inline]
    fn from(value: Uint53) -> Self {
        ContestDataFieldTally(value)
    }
}

impl TryFrom<i64> for ContestDataFieldTally {
    type Error = Uint53Error;
    /// One can try to make a [`ContestDataFieldTally`] from an [`i64`].
    #[inline]
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(ContestDataFieldTally(value.try_into()?))
    }
}

impl TryFrom<u64> for ContestDataFieldTally {
    type Error = Uint53Error;
    /// One can try to make a [`ContestDataFieldTally`] from a [`u64`].
    #[inline]
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(ContestDataFieldTally(value.try_into()?))
    }
}

impl TryFrom<u128> for ContestDataFieldTally {
    type Error = Uint53Error;
    /// One can try to make a [`ContestDataFieldTally`] from a [`u128`].
    #[inline]
    fn try_from(value: u128) -> Result<Self, Self::Error> {
        Ok(ContestDataFieldTally(value.try_into()?))
    }
}

impl TryFrom<ContestDataFieldTally> for i8 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`i8`] from a [`ContestDataFieldTally`].
    #[inline]
    fn try_from(cdft: ContestDataFieldTally) -> Result<Self, Self::Error> {
        cdft.0.try_into()
    }
}

impl TryFrom<ContestDataFieldTally> for u8 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`u8`] from a [`ContestDataFieldTally`].
    #[inline]
    fn try_from(cdft: ContestDataFieldTally) -> Result<Self, Self::Error> {
        cdft.0.try_into()
    }
}

impl TryFrom<ContestDataFieldTally> for u16 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`u16`] from a [`ContestDataFieldTally`].
    #[inline]
    fn try_from(cdft: ContestDataFieldTally) -> Result<Self, Self::Error> {
        cdft.0.try_into()
    }
}

impl TryFrom<ContestDataFieldTally> for u32 {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`u32`] from a [`ContestDataFieldTally`].
    #[inline]
    fn try_from(cdft: ContestDataFieldTally) -> Result<Self, Self::Error> {
        cdft.0.try_into()
    }
}

impl From<ContestDataFieldTally> for Uint53 {
    /// A [`Uint53`] can always be made from a [`ContestDataFieldTally`].
    fn from(cdft: ContestDataFieldTally) -> Self {
        cdft.0
    }
}

impl From<ContestDataFieldTally> for i64 {
    /// An [`i64`] can always be made from a [`ContestDataFieldTally`].
    fn from(cdft: ContestDataFieldTally) -> Self {
        cdft.0.into()
    }
}

impl From<ContestDataFieldTally> for u64 {
    /// A [`u64`] can always be made from a [`ContestDataFieldTally`].
    fn from(cdft: ContestDataFieldTally) -> Self {
        cdft.0.into()
    }
}

impl TryFrom<ContestDataFieldTally> for isize {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`isize`] from a [`ContestDataFieldTally`].
    #[inline]
    fn try_from(cdft: ContestDataFieldTally) -> Result<Self, Self::Error> {
        cdft.0.try_into()
    }
}

impl TryFrom<ContestDataFieldTally> for usize {
    type Error = std::num::TryFromIntError;
    /// One can try to make a [`usize`] from a [`ContestDataFieldTally`].
    #[inline]
    fn try_from(cdft: ContestDataFieldTally) -> Result<Self, Self::Error> {
        cdft.0.try_into()
    }
}

impl From<ContestDataFieldTally> for i128 {
    /// An [`i128`] can always be made from a [`ContestDataFieldTally`].
    fn from(cdft: ContestDataFieldTally) -> Self {
        cdft.0.into()
    }
}

impl From<ContestDataFieldTally> for u128 {
    /// A [`u128`] can always be made from a [`ContestDataFieldTally`].
    fn from(cdft: ContestDataFieldTally) -> Self {
        cdft.0.into()
    }
}

impl HasIndexType for ContestDataFieldTally {
    type IndexTypeParam = Ciphertext;
}

/// Same type as [`CiphertextIndex`], [`ContestOptionIndex`](crate::election_manifest::ContestOptionIndex),
/// [`ContestOptionFieldPlaintextIndex`](crate::contest_option_fields::ContestOptionFieldPlaintextIndex),
/// [`ContestDataFieldIndex`](crate::contest_data_fields_plaintexts::ContestDataFieldIndex), etc.
pub type ContestDataFieldTallyIndex = CiphertextIndex;

//-------------------------------------------------------------------------------------------------|

/// Tallies (plaintext) of the data fields (including voter selectable options) of a single contest.
///
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    derive_more::Deref,
    derive_more::DerefMut,
    derive_more::From
)]
pub struct ContestTallies(
    //#[derive_more::from]
    Vec1<ContestDataFieldTally>,
);

impl ContestTallies {
    /// Creates a zero-initialized tally of the specified `len`.
    pub fn new_zeroed_of_len(len: usize) -> EgResult<Self> {
        let v: Vec<ContestDataFieldTally> = vec![ContestDataFieldTally::zero(); len];
        Ok(ContestTallies(v.try_into()?))
    }

    /// Creates a [`Vec1`] with a zero-initialized entry for every contest in an election manifest.
    pub fn vec1_for_all_contests_zeroed(
        election_manifest: &ElectionManifest,
    ) -> EgResult<Vec1<Self>> {
        let mut contest_tallies =
            Vec1::<ContestTallies>::with_capacity(election_manifest.contests().len());
        for contest in election_manifest.contests().iter() {
            let zero_tallies = ContestTallies::new_zeroed_of_len(contest.num_data_fields())?;
            contest_tallies.try_push(zero_tallies)?;
        }
        Ok(contest_tallies)
    }
}

impl HasIndexType for ContestTallies {
    type IndexTypeParam = Contest;
}

/// Same type as [`ContestIndex`](crate::election_manifest::ContestIndex).
pub type ContestTalliesIndex = crate::election_manifest::ContestIndex;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    //use anyhow::{anyhow, bail, ensure, Context, Result};
    use anyhow::Result;

    use super::*;
    //?use insta::assert_ron_snapshot;

    #[test]
    fn t10() -> Result<()> {
        let _u53 = Uint53::from(0_u8);

        // ContestDataFieldTally()
        //?assert!();
        //?assert_eq!();
        //?assert_ron_snapshot!(, @"");
        Ok(())
    }
}
