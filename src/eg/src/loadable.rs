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
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::io::Cursor;
use std::{borrow::Cow, ops::Deref};

use anyhow::Context;

use crate::{
    eg::Eg,
    errors::{EgError, EgResult, EgValidateError},
    resource::{ProduceResource, ProduceResourceExt},
    validatable::{Validatable, Validated},
};

pub trait KnowsFriendlyTypeName {
    /// Returns a friendly name for the type, if known.
    ///
    /// E.g., "ElectionManifest".
    ///
    /// This is used in various messages.
    fn friendly_type_name() -> Cow<'static, str>;
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[allow(non_camel_case_types)]
pub enum EgLoadingError {
    #[error(transparent)]
    ValidationError(#[from] EgValidateError),

    #[error("[Ln {line}, Col {column}] Reading `{type_name}`: {s}")]
    ParsingJsonError {
        line: usize,
        column: usize,
        type_name: String,
        s: String,
    },

    #[error(transparent)]
    EgError(Box<EgError>),
}

impl EgLoadingError {
    fn from_serde_json_error(sj_err: serde_json::Error, type_name: Cow<'static, str>) -> Self {
        EgLoadingError::ParsingJsonError {
            line: sj_err.line(),
            column: sj_err.column(),
            type_name: type_name.into_owned(),
            s: format!("{:?} error: {:?}", sj_err.classify(), sj_err),
        }
    }
}

impl From<EgError> for EgLoadingError {
    /// A [`EgLoadingError`] can always be made from a [`EgError`].
    fn from(src: EgError) -> Self {
        match src {
            EgError::LoadingError(self_) => self_,
            EgError::DuringLoading(bx_egerror) => EgLoadingError::EgError(bx_egerror),
            _ => EgLoadingError::EgError(Box::new(src)),
        }
    }
}

impl From<anyhow::Error> for EgLoadingError {
    /// A [`EgLoadingError`] can always be made from a [`anyhow::Error`].
    #[inline]
    fn from(src: anyhow::Error) -> Self {
        EgError::from(src).into()
    }
}

//=================================================================================================|

/// Trait for loading a `Self: Validatable`.
pub trait LoadableFromStdIoReadValidatable:
    Validatable + KnowsFriendlyTypeName + serde::de::DeserializeOwned + Sized
where
    for<'de> Self: serde::de::Deserialize<'de>,
{
    /// Reads `Self: Validatable` from `&str`.
    ///
    /// Does not verify that it is *the* canonical byte sequence, or validate the resulting object.
    ///
    /// It can be either the canonical or pretty JSON representation.
    fn from_json_str_validatable(s: &str) -> EgResult<Self> {
        let mut cursor = Cursor::new(s);
        Self::from_stdioread_validatable(&mut cursor)
    }

    /// Reads `Self: Validatable` from a byte sequence.
    ///
    /// Does not verify that it is *the* canonical byte sequence, or validate the resulting object.
    ///
    /// It can be either the canonical or pretty JSON representation.
    fn from_bytes_validatable(bytes: &[u8]) -> EgResult<Self> {
        let mut cursor = Cursor::new(bytes);
        Self::from_stdioread_validatable(&mut cursor)
    }

    /// Reads `Self: Validatable` from a [`std::io::Read`].
    ///
    /// Does not verify that it is *the* canonical byte sequence, or validate the resulting object.
    ///
    /// It can be either the canonical or pretty JSON representation.
    fn from_stdioread_validatable(stdioread: &mut dyn std::io::Read) -> EgResult<Self> {
        serde_json::from_reader(stdioread)
            .map_err(|sje| EgLoadingError::from_serde_json_error(sje, Self::friendly_type_name()))
            .with_context(|| format!("Reading {} from stdio", Self::friendly_type_name()))
            .map_err(Into::<EgError>::into)
    }
}

impl<T> LoadableFromStdIoReadValidatable for T
where
    T: Validatable + KnowsFriendlyTypeName + serde::de::DeserializeOwned + Sized,
    for<'de> T: serde::de::Deserialize<'de>,
{
}

/// Trait for loading a `Self: Validated`.
pub trait LoadableFromStdIoReadValidated: Validated + KnowsFriendlyTypeName + Sized
where
    <Self as Validated>::ValidatedFrom: LoadableFromStdIoReadValidatable
        + KnowsFriendlyTypeName
        + serde::de::DeserializeOwned
        + Sized,
    for<'de> <Self as Validated>::ValidatedFrom: serde::de::Deserialize<'de>,
{
    /// Reads `Self: Validated` from `&str`.
    ///
    /// Does not verify that it is *the* canonical byte sequence, or validate the resulting object.
    ///
    /// It can be either the canonical or pretty JSON representation.
    fn from_json_str_validated(
        s: &str,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<Self>
    where
        for<'de> <Self as Validated>::ValidatedFrom: serde::de::Deserialize<'de>,
    {
        let mut cursor = Cursor::new(s);
        Self::from_stdioread_validated(&mut cursor, produce_resource)
    }

    /// Reads `Self: Validated` from a byte sequence.
    ///
    /// Does not verify that it is *the* canonical byte sequence, or validate the resulting object.
    ///
    /// It can be either the canonical or pretty JSON representation.
    fn from_bytes_validated(
        bytes: &[u8],
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<Self>
    where
        for<'de> <Self as Validated>::ValidatedFrom: serde::de::Deserialize<'de>,
    {
        let mut cursor = Cursor::new(bytes);
        Self::from_stdioread_validated(&mut cursor, produce_resource)
    }

    /// Reads `Self: Validated` from a [`std::io::Read`].
    ///
    /// Does not verify that it is *the* canonical byte sequence, or validate the resulting object.
    ///
    /// It can be either the canonical or pretty JSON representation.
    fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<Self>
    where
        for<'de> <Self as Validated>::ValidatedFrom: serde::de::Deserialize<'de>,
    {
        <<Self as Validated>::ValidatedFrom as LoadableFromStdIoReadValidatable>::from_stdioread_validatable(stdioread)
            .and_then(|self_| <Self as Validated>::try_validate_from(self_, produce_resource))
            .with_context(|| format!("Reading {} from stdio", Self::friendly_type_name()))
            .map_err(Into::<EgError>::into)
    }
}

impl<T> LoadableFromStdIoReadValidated for T
where
    T: Validated + KnowsFriendlyTypeName + Sized,
    <T as Validated>::ValidatedFrom: LoadableFromStdIoReadValidatable
        + KnowsFriendlyTypeName
        + serde::de::DeserializeOwned
        + Sized,
    for<'de> <T as Validated>::ValidatedFrom: serde::de::Deserialize<'de>,
{
}
