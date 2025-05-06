// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::collections::BTreeMap;

use crate::{
    algebra::FieldElement,
    ciphertext::Ciphertext,
    contest::ContestIndex,
    contest_data_fields_ciphertexts::ContestDataFieldsCiphertexts,
    eg::Eg,
    fixed_parameters::{FixedParameters, FixedParametersTrait, FixedParametersTraitExt},
};

//=================================================================================================|

/// A scaled version of [`ContestDataFieldsCiphertexts`].
///
/// This means that each encrypted vote on the contest has been scaled by a factor. It is trusted that the encrypted ciphertexts in a
/// [`ContestEncryptedScaled`] really are the ones from a
/// [`ContestDataFieldsCiphertexts`] scaled by a factor.
///
/// Contains no proofs.
#[derive(PartialEq, Eq)]
pub struct ContestEncryptedScaled {
    /// Scaled encrypted voter selection vector.
    pub selection: Vec<Ciphertext>,
}

impl ContestEncryptedScaled {
    /// Verify that the [`ContestEncryptedScaled`] stems from a given [`ContestDataFieldsCiphertexts`] by
    /// scaling with a given factor.
    pub fn verify(
        &self,
        origin: ContestDataFieldsCiphertexts,
        factor: &FieldElement,
        fixed_parameters: &FixedParameters,
    ) -> bool {
        origin.scale(fixed_parameters, factor) == *self
    }
}

//-------------------------------------------------------------------------------------------------|

/// Scaled version of [`Ballot`](crate::ballot::Ballot). This means that each encrypted vote in the ballot
/// has been scaled by some factor. A [`BallotScaled`] does not contain any proofs.
pub struct BallotScaled {
    /// Contests in this ballot
    pub contests: BTreeMap<ContestIndex, ContestEncryptedScaled>,
}
