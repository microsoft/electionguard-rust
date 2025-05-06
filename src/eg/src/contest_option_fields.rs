// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use serde::{Deserialize, Serialize};

//
use util::{
    uint31::Uint31,
    vec1::{HasIndexType, Vec1},
};

use crate::{
    ciphertext::{Ciphertext, CiphertextIndex},
    eg::Eg,
    errors::{EgError, EgResult},
};

//=================================================================================================|

/// A 1-based index of a [`ContestOptionFieldPlaintext`] in the order it is defined within its
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
pub type ContestOptionFieldPlaintextIndex = CiphertextIndex;

impl HasIndexType for ContestOptionFieldPlaintext {
    type IndexTypeParam = Ciphertext;
}

//-------------------------------------------------------------------------------------------------|

/// Value of a single contest selectable option value.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ContestOptionFieldPlaintext(Uint31);

impl ContestOptionFieldPlaintext {
    /// Returns a new [`ContestOptionFieldPlaintext`] with a value of zero.
    pub fn zero() -> Self {
        Self(Uint31::zero())
    }

    /// A [`ContestOptionFieldPlaintext`] can be made from any type that can be converted into a
    /// [`Uint31`].
    pub fn new<T: Into<Uint31>>(t: T) -> Self {
        Self(t.into())
    }

    /// A [`ContestOptionFieldPlaintext`] can be made from any type that can be converted into a
    /// [`Uint31`].
    pub fn try_new<T>(t: T) -> EgResult<Self>
    where
        T: TryInto<Uint31>,
        <T as TryInto<Uint31>>::Error: Into<EgError>,
    {
        TryInto::<Uint31>::try_into(t).map_err(Into::into).map(Self)
    }
}

/// A [`ContestOptionFieldPlaintext`] can be made from a [`u8`].
impl From<u8> for ContestOptionFieldPlaintext {
    fn from(value: u8) -> Self {
        Self(value.into())
    }
}

/// A [`ContestOptionFieldPlaintext`] can be made from a [`u16`].
impl From<u16> for ContestOptionFieldPlaintext {
    fn from(value: u16) -> Self {
        Self(value.into())
    }
}

/// A [`ContestOptionFieldPlaintext`] can be made from a [`Uint31`].
impl From<Uint31> for ContestOptionFieldPlaintext {
    fn from(value: Uint31) -> Self {
        Self(value)
    }
}

/// A [`Uint31`] can be made from a [`ContestOptionFieldPlaintext`].
impl From<ContestOptionFieldPlaintext> for Uint31 {
    fn from(cofpt: ContestOptionFieldPlaintext) -> Self {
        cofpt.0
    }
}

/// A [`u32`] can be made from a [`ContestOptionFieldPlaintext`].
impl From<ContestOptionFieldPlaintext> for u32 {
    fn from(cofpt: ContestOptionFieldPlaintext) -> Self {
        cofpt.0.into()
    }
}

/// A `usize` can be made from a [`ContestOptionFieldPlaintext`].
impl From<ContestOptionFieldPlaintext> for usize {
    fn from(cofpt: ContestOptionFieldPlaintext) -> Self {
        static_assertions::const_assert!(31 <= usize::BITS);
        u32::from(cofpt) as usize
    }
}

/// A [`u64`] can be made from a [`ContestOptionFieldPlaintext`].
impl From<ContestOptionFieldPlaintext> for u64 {
    fn from(cofpt: ContestOptionFieldPlaintext) -> Self {
        cofpt.0.into()
    }
}

//-------------------------------------------------------------------------------------------------|

/// Values of the voter selectable options of a single contest.
///
/// - `contest_option_fields_plaintexts` should have the same length as the
///   number of options in the contest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContestOptionFieldsPlaintexts(Vec1<ContestOptionFieldPlaintext>);

impl ContestOptionFieldsPlaintexts {
    /// Try to make a [`ContestOptionFieldsPlaintexts`] from any type that
    /// does `IntoIterator<Item = T>` where `T` can [`Into`] a [`ContestOptionFieldPlaintext`].
    pub fn try_new_from<I, T>(iter: I) -> EgResult<Self>
    where
        I: IntoIterator<Item = T>,
        T: TryInto<Uint31> + Sized,
    {
        let mut v1_cofp = Vec1::<ContestOptionFieldPlaintext>::new();
        for (ix0, value) in iter.into_iter().enumerate() {
            //match Uint31::try_from(value)
            match TryInto::<Uint31>::try_into(value) {
                Ok(valu31) => {
                    v1_cofp.try_push(ContestOptionFieldPlaintext::new(valu31))?;
                }
                Err(_) => {
                    return Err(EgError::ContestOptionFieldsPlaintextsNew(ix0 + 1));
                }
            }
        }

        Ok(Self(v1_cofp))
    }

    pub fn into_inner(self) -> Vec1<ContestOptionFieldPlaintext> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[ContestOptionFieldPlaintext] {
        self.0.as_zero_based_slice()
    }
}

impl AsRef<ContestOptionFieldsPlaintexts> for ContestOptionFieldsPlaintexts {
    #[inline]
    fn as_ref(&self) -> &ContestOptionFieldsPlaintexts {
        self
    }
}

/// Access to the inner [`Vec1`] of [`ContestOptionFieldsPlaintexts`].
impl AsRef<Vec1<ContestOptionFieldPlaintext>> for ContestOptionFieldsPlaintexts {
    fn as_ref(&self) -> &Vec1<ContestOptionFieldPlaintext> {
        &self.0
    }
}

impl From<Vec1<ContestOptionFieldPlaintext>> for ContestOptionFieldsPlaintexts {
    fn from(v: Vec1<ContestOptionFieldPlaintext>) -> Self {
        Self(v)
    }
}

/// You can try to make a [`ContestOptionFieldsPlaintexts`] from any slice of a type that
/// can [`Into`] a [`ContestOptionFieldPlaintext`].
impl<T> TryFrom<&[T]> for ContestOptionFieldsPlaintexts
where
    T: Into<ContestOptionFieldPlaintext> + Clone + Sized,
{
    type Error = EgError;
    fn try_from(src: &[T]) -> EgResult<Self> {
        let v: Vec<ContestOptionFieldPlaintext> = src.iter().cloned().map(Into::into).collect();

        // Unwrap() is justified here because we have already checked that the length is valid.
        #[allow(clippy::unwrap_used)]
        let vec1 = Vec1::<ContestOptionFieldPlaintext>::try_from(v)?;

        Ok(Self(vec1))
    }
}
