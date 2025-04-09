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
use std::sync::Arc;
use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

use async_trait::async_trait;
use either::Either;
use strum::EnumCount;
use util::{csrng::Csrng, vec1::Vec1};

use crate::resource_producer::RpOp;
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
    resource::{MayBeResource, ProduceResource, ProduceResourceExt},
};

/// Custom [`Error`](std::error::Error) type for common errors that may result from a
/// validation. The [`ValidationRequires...`](EgValidateError::ValidationRequiresCsprng)
/// group of errors are generally retryable after supplying the needed information.
///
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[allow(non_camel_case_types)]
pub enum EgValidateError {
    #[error("Validation error: {0}")]
    EgError(#[from] Box<EgError>),

    #[error("Validation error: {0}")]
    Other(String),

    #[error("Validation error: {0}")]
    Str(&'static str),
}

impl From<EgError> for EgValidateError {
    /// A [`EgValidateError`] can always be made from a [`EgError`].
    fn from(src: EgError) -> Self {
        match src {
            EgError::ValidationError(self_) => self_,
            EgError::DuringValidation(bx_egerror) => EgValidateError::EgError(bx_egerror),
            _ => EgValidateError::EgError(Box::new(src)),
        }
    }
}

impl From<anyhow::Error> for EgValidateError {
    /// A [`EgValidateError`] can always be made from a [`anyhow::Error`].
    #[inline]
    fn from(src: anyhow::Error) -> Self {
        EgError::from(src).into()
    }
}

impl From<String> for EgValidateError {
    fn from(s: String) -> Self {
        EgValidateError::Other(s)
    }
}

//=================================================================================================|

//? TODO: development test code
#[async_trait::async_trait(?Send)]
pub trait ValidatableUnsized {
    /// Tries to validate [`Arc<Self>`] into [`Arc<dyn ValidatedUnsized>`].
    ///
    /// May [`clone()`] if necessary.
    async fn arc_validate_into_rc(
        self: std::sync::Arc<Self>,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<Arc<dyn ValidatedUnsized>>;
}

//? TODO: development test code
/// Trait for types that could possibly implement the [`ValidatableUnsized`] trait.
pub trait MayBeValidatableUnsized: Send + Sync {
    /// May return [`&self`](self) as a [`&dyn ValidatableUnsized`](ValidatableUnsized).
    fn opt_as_validatableunsized(&self) -> Option<&dyn ValidatableUnsized>;
}

//? TODO: development test code
impl<T> MayBeValidatableUnsized for T
where
    T: ValidatableUnsized + Send + Sync,
{
    fn opt_as_validatableunsized(&self) -> Option<&dyn ValidatableUnsized> {
        Some(self)
    }
}

//=================================================================================================|

//? TODO: development test code
pub trait ValidatedUnsized {}

//=================================================================================================|

pub trait Validatable: MayBeResource + Sized {
    type ValidatedInto: Validated;
}

//=================================================================================================|

#[async_trait(?Send)]
pub trait Validated: MayBeResource + Into<Self::ValidatedFrom> + Validatable + Sized {
    type ValidatedFrom: Validatable;

    /// Tries to validate a `src` having type [`Self::ValidatedFrom`] into [`Self`].
    async fn try_validate_from_async(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        src: Self::ValidatedFrom,
    ) -> EgResult<Self> {
        Self::try_validate_from_async_impl_(produce_resource, src).await
    }

    /// Tries to validate a `src` having type [`Self::ValidatedFrom`] into [`Self`].
    fn try_validate_from(
        src: Self::ValidatedFrom,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<Self> {
        async_global_executor::block_on(Self::try_validate_from_async(produce_resource, src))
    }

    /// Tries to validate a `src` having type [`Self::ValidatedFrom`] into [`Self`].
    ///
    /// Implement this one.
    async fn try_validate_from_async_impl_(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        src: Self::ValidatedFrom,
    ) -> EgResult<Self>;

    /// Tries to validate `src` having type [`Arc<Self::ValidatedFrom>`] into [`Self`].
    ///
    /// May [`clone()`] if necessary.
    fn try_validate_from_arc(
        src_arc: Arc<Self::ValidatedFrom>,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<Self>
    where
        Self::ValidatedFrom: Clone,
    {
        let src = Arc::unwrap_or_clone(src_arc);
        Self::try_validate_from(src, produce_resource)
    }

    /// Tries to un-validate `self` back into [`Self::ValidatedFrom`].
    fn un_validate(self) -> Self::ValidatedFrom {
        self.into()
    }

    /// Tries to un-validate `src` having type [`Arc<Self>`] into [`Self::ValidatedFrom`].
    ///
    /// May [`clone()`] if necessary.
    fn un_validate_from_rc(arc_self: Arc<Self>) -> Self::ValidatedFrom
    where
        Self: Clone,
    {
        let self_ = Arc::unwrap_or_clone(arc_self);
        self_.un_validate()
    }

    fn re_validate(
        self,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<Self> {
        let un_validated = self.un_validate();

        <Self as Validated>::try_validate_from(un_validated, produce_resource)
    }
}

//=================================================================================================|
