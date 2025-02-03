// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)]
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code

use std::cell::{Ref, RefCell, RefMut};
use std::rc::Rc;
use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

use either::Either;
use maybe_owned::{MaybeOwned, MaybeOwnedMut};
use strum::EnumCount;
use util::{csrng::Csrng, vec1::Vec1};

use crate::{
    eg::Eg,
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    errors::{EgError, EgResult},
    extended_base_hash::ExtendedBaseHash_H_E,
    guardian::{GuardianIndex, GuardianKeyPurpose},
    guardian_public_key::GuardianPublicKey,
    guardian_secret_key::GuardianSecretKey,
    hashes::Hashes,
    joint_public_key::JointPublicKey,
    pre_voting_data::PreVotingData,
    resource::MayBeResource,
};

/// Custom [`Error`](std::error::Error) type for common errors that may result from a
/// validation. The [`ValidationRequires...`](EgValidateError::ValidationRequiresCsprng)
/// group of errors are generally retryable after supplying the needed information.
///
#[derive(thiserror::Error, Debug)]
#[allow(non_camel_case_types)]
pub enum EgValidateError {
    /*
    #[error("Validation of this type requires a `Csprng` in `Eg`.")]
    ValidationRequiresCsprng,

    #[error("`Eg` already has a `Csprng`.")]
    ValidationAlreadyHasCsprng,

    #[error("Validation of this type requires the `ElectionParameters` (or `PreVotingData`) in `Eg`.")]
    ValidationRequiresElectionParameters,

    #[error(
        "Validation of this type requires the `Hashes` (or `PreVotingData`) in `Eg`."
    )]
    ValidationRequiresHashes,

    #[error("Validation of this type requires the `ElectionManifest` (or `PreVotingData`) in `Eg`.")]
    ValidationRequiresElectionManifest,

    #[error("Validation of this type requires the `ExtendedBaseHash` (or `PreVotingData`) in `Eg`.")]
    ValidationRequiresExtendedBaseHash,

    #[error("Validation of this type requires the `PreVotingData` in `Eg`.")]
    ValidationRequiresPreVotingData,

    #[cfg(any(feature = "eg-allow-test-data-generation", test))]
    #[error("(Test builds only) Validation of this type requires the guardian secret keys in `Eg`.")]
    ValidationRequiresGuardianSecretKeys,

    #[error("Validation of this type requires the guardian public keys in `Eg`.")]
    ValidationRequiresGuardianPublicKeys,

    #[error("Validation of this type requires the `JointPublicKey` (or `PreVotingData`) in `Eg`.")]
    ValidationRequiresJointPublicKey,

    #[error("The validation info already has a `{0}`")]
    ValidationInfoValueAlreadyExists(&'static str),

    #[error("The validation info field `{0}` is already (mutably) in use")]
    ValidationInfoValueAlreadyMutablyInUse(&'static str),
    // */
    #[error("Validation error: {0}")]
    EgError(#[from] Box<EgError>),

    #[error("Validation error: {0}")]
    Other(String),
}

impl From<EgError> for EgValidateError {
    fn from(e: EgError) -> Self {
        EgValidateError::EgError(Box::new(e))
    }
}

impl From<anyhow::Error> for EgValidateError {
    fn from(e: anyhow::Error) -> Self {
        EgValidateError::Other(e.to_string())
    }
}

impl From<String> for EgValidateError {
    fn from(s: String) -> Self {
        EgValidateError::Other(s)
    }
}

//=================================================================================================|

/* #[derive(Debug, strum_macros::EnumDiscriminants)]
#[strum_discriminants(name(AsymmetricKeyKind))]
pub enum AsymmetricKey {
    Secret(GuardianSecretKey),
    Public(GuardianPublicKey),
}
 */
//=================================================================================================|

pub trait Validatable: MayBeResource + Sized {
    type ValidatedInto: Validated;
}

//=================================================================================================|

pub trait Validated: MayBeResource + Into<Self::ValidatedFrom> + Validatable + Sized {
    type ValidatedFrom: Validatable;

    /// Tries to validate a `src` having type [`Self::ValidatedFrom`] into [`Self`].
    fn try_validate_from(src: Self::ValidatedFrom, eg: &Eg) -> EgResult<Self>;

    /// Tries to validate `src` having type [`Rc<Self::ValidatedFrom>`] into [`Self`].
    ///
    /// May [`clone()`] if necessary.
    fn try_validate_from_rc(src_rc: Rc<Self::ValidatedFrom>, eg: &Eg) -> EgResult<Self>
    where
        Self::ValidatedFrom: Clone,
    {
        let src = Rc::unwrap_or_clone(src_rc);
        Self::try_validate_from(src, eg)
    }

    fn un_validate(self, eg: &Eg) -> EgResult<Self::ValidatedFrom> {
        Ok(self.into())
    }

    fn re_validate(self, eg: &Eg) -> EgResult<Self> {
        let un_validated = self.un_validate(eg)?;

        <Self as Validated>::try_validate_from(un_validated, eg)
    }
}

//=================================================================================================|
