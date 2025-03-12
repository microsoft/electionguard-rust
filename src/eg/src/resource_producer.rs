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

use std::{
    any::Any,
    borrow::Cow,
    //path::{Path, PathBuf},
    sync::Arc,
    //str::FromStr,
    //sync::OnceLock,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    sync::LazyLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};
use rand::{Rng, RngCore, distr::Uniform};
//use serde::{Deserialize, Serialize};
use static_assertions::{assert_impl_all, assert_obj_safe};
use tracing::{debug, debug_span, error, info, info_span, instrument, trace, trace_span, warn};
use util::abbreviation::Abbreviation;

use crate::{
    eg::Eg,
    errors::{EgError, EgResult},
    //guardian_secret_key::GuardianIndex,
    resource::{ProductionBudget, Resource, ResourceFormat, ResourceIdFormat},
};
pub use crate::{
    resource_producer_registry::{
        FnNewResourceProducer, GatherResourceProducerRegistrationsFnWrapper,
        ResourceProducerCategory, ResourceProducerRegistration, ResourceProducerRegistry,
    },
    resource_production::RpOp,
};

//=================================================================================================|

#[allow(unreachable_patterns)] //? TODO: Remove temp development code
#[derive(
    Clone,
    Debug,
    derive_more::Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize
)]
pub enum ValidReason {
    /// The Resource is inherently valid, valid due to its method of construction, or all possible
    /// values of the type are equally valid.
    Inherent,

    /// Produced by validating a [`ConcreteType`](ResourceFormat::ConcreteType)
    /// into its corresponding [`ValidatedElectionDataObject`](ResourceFormat::ValidatedElectionDataObject).
    ///
    /// See the [`Validated::try_validate_from()`](crate::validatable::Validated::try_validate_from)
    /// trait function.
    #[display("ValidatedFrom({_0}, {_1})")]
    ValidatedFrom(ResourceFormat, Box<ResourceSource>),

    /// Produced by extracting information entirely from already [`ValidatedElectionDataObject`](ResourceFormat::ValidatedElectionDataObject)s.
    #[display("ValidlyExtractedFrom({_0}, {_1})")]
    ValidlyExtractedFrom(ResourceFormat, Box<ResourceSource>),
}

/// Describes the source used to [produce](ResourceProducer) a [`Resource`](Resource).
#[allow(unreachable_patterns)] //? TODO: Remove temp development code
#[derive(
    Clone,
    Debug,
    derive_more::Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize
)]
pub enum ResourceSource {
    /// Provided via the [`Eg::provide_resource`] function.
    Provided,

    /// Obtained from cache.
    #[display("Cache({_0})")]
    Cache(Box<ResourceSource>),

    /// Produced directly as example data.
    #[cfg(any(feature = "eg-allow-test-data-generation", test))]
    #[display("ExampleData({_0})")]
    ExampleData(ResourceFormat),

    /// Produced by deserializing an object from persisted bytes.
    Depersisted,

    /// Produced by constructing a new object from available information.
    #[display("Constructed({_0})")]
    Constructed(ResourceFormat),

    /// Produced by serializing an existing or available object.
    #[display("SerializedFrom({_0})")]
    SerializedFrom(ResourceFormat, Box<ResourceSource>),

    /// Known `Valid`, reason given.
    Valid(ValidReason),

    /// Produced by UN-validating a [`ValidatedElectionDataObject`](ResourceFormat::ValidatedElectionDataObject)
    /// back into its original unvalidated [`ConcreteType`](ResourceFormat::ConcreteType).
    ///
    /// See the [`Validated::un_validate()`](crate::validatable::Validated::un_validate)
    /// trait function.
    #[display("UnValidatedFrom({_0})")]
    UnValidatedFrom(Box<ResourceSource>),

    //? TODO This situation needs design thought.
    TodoItsComplicated,
}

impl ResourceSource {
    pub fn constructed_concretetype() -> Self {
        Self::Constructed(ResourceFormat::ConcreteType)
    }

    pub fn constructed_validatededo() -> Self {
        Self::Constructed(ResourceFormat::ValidElectionDataObject)
    }

    pub fn exampledata_slicebytes() -> Self {
        Self::ExampleData(ResourceFormat::SliceBytes)
    }

    pub fn serialized_from(fmt: ResourceFormat, rsrc: ResourceSource) -> Self {
        let bx_rsrc = Box::new(rsrc);
        Self::SerializedFrom(fmt, bx_rsrc)
    }

    pub fn slicebytes_serializedfrom_constructed_concretetype() -> Self {
        Self::serialized_from(ResourceFormat::SliceBytes, Self::constructed_concretetype())
    }

    pub fn validated_from(fmt: ResourceFormat, rsrc: ResourceSource) -> Self {
        let bx_rsrc = Box::new(rsrc);
        Self::Valid(ValidReason::ValidatedFrom(fmt, bx_rsrc))
    }

    pub fn validly_extracted_from(rsrc: ResourceSource) -> Self {
        let bx_rsrc = Box::new(rsrc);
        Self::Valid(ValidReason::ValidlyExtractedFrom(
            ResourceFormat::ValidElectionDataObject,
            bx_rsrc,
        ))
    }

    pub fn un_validated_from(rsrc: ResourceSource) -> Self {
        let bx_rsrc = Box::new(rsrc);
        Self::UnValidatedFrom(bx_rsrc)
    }

    /// Returns `true` iff the [`ResourceSource`] is [`Cache`](ResourceSource::Cache).
    pub fn is_cache(&self) -> bool {
        matches!(self, &ResourceSource::Cache(_))
    }

    /// Returns `true` iff the [`ResourceSource`] derives from [`ExampleData`], though possibly indirectly.
    pub fn derives_from_test_data(&self) -> bool {
        #[cfg(any(feature = "eg-allow-test-data-generation", test))]
        {
            let mut src = self;
            loop {
                match src {
                    ResourceSource::Cache(bx_src) => {
                        src = bx_src.as_ref();
                    }
                    ResourceSource::ExampleData(_) => {
                        return true;
                    }
                    ResourceSource::SerializedFrom(fmt, bx_src) => {
                        src = bx_src.as_ref();
                    }
                    ResourceSource::Valid(ValidReason::ValidatedFrom(fmt, bx_src)) => {
                        src = bx_src.as_ref();
                    }
                    _ => {
                        break;
                    }
                }
            }
        }
        false
    }
}

impl Abbreviation for ResourceSource {
    /// Returns an excessively short string hinting at the value. Useful only for logging.
    fn abbreviation(&self) -> Cow<'static, str> {
        self.to_string().into()
    }
}

//=================================================================================================|

/// [`Result::Err`](std::result::Result) type of a data resource production operation.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[allow(non_camel_case_types)]
pub enum ResourceProductionError {
    //#[error(transparent)]
    //EgError(#[from] Box<EgError>),
    #[error("No way was found to produce the requested `{0}` as `{1}`.",
    ridfmt.rid, ridfmt.fmt)]
    NoProducerFound { ridfmt: ResourceIdFormat },

    #[error("While attempting to load `{0}` as `{1}`, failed to produce a needed dependency: {dep_err}",
        ridfmt_request.rid, ridfmt_request.fmt)]
    DependencyProductionError {
        ridfmt_request: ResourceIdFormat,
        dep_err: Box<ResourceProductionError>,
    },

    #[error("The Eg data resource cache is already (mutably) in use.")]
    ResourceCacheAlreadyMutablyInUse,

    #[error("While attempting to load `{0}` as `{1}`, recursion was detected: {chain}",
        ridfmt_request.rid, ridfmt_request.fmt)]
    RecursionDetected {
        ridfmt_request: ResourceIdFormat,
        chain: String,
    },

    #[error(
        "The already-stored resource, `{ridfmt}` from `{stored_resource_source}`, is not being replaced with `{rpr_err:?}`."
    )]
    ResourceAlreadyStored {
        ridfmt: ResourceIdFormat,
        stored_resource_source: ResourceSource,
        rpr_err: Box<ResourceProductionError>,
    },

    #[error("While attempting to load `{0}` as `{1}`, it became no longer needed.",
        ridfmt.rid, ridfmt.fmt)]
    ResourceNoLongerNeeded { ridfmt: ResourceIdFormat },

    #[error(
        "Expecting to be asked to produce `{ridfmt_expected:?}` but was asked for `{ridfmt_requested:?}` instead."
    )]
    UnexpectedResourceIdFormatRequested {
        ridfmt_expected: ResourceIdFormat,
        ridfmt_requested: ResourceIdFormat,
    },

    #[error(
        "The format for the resource provided `{ridfmt_provided}` does not match the resource's belief about its format `{ridfmt_internal}`."
    )]
    UnexpectedResourceIdFormatProvided {
        ridfmt_provided: ResourceIdFormat,
        ridfmt_internal: ResourceIdFormat,
    },

    #[error(
        "The data resource provider for example data is already configured, but it has different values."
    )]
    ResourceProducerExampleDataMismatch,

    #[error("Could not downcast data resource `{0}` from `{src_resource_source}` of type `{src_type}` to type `{target_type}`. The expected source type (if known) was: {1}",
        src_ridfmt.abbreviation(), opt_src_type_expected.clone().unwrap_or_else(|| "[Unknown]".to_string()))]
    CouldntDowncastResource {
        src_ridfmt: ResourceIdFormat,
        src_resource_source: ResourceSource,
        src_type: String,
        opt_src_type_expected: Option<String>,
        target_type: String,
    },

    #[error("The request was for {requested}, but {produced} was produced unexpectedly.")]
    UnexpectedResourceIdFormatProduced {
        requested: ResourceIdFormat,
        produced: ResourceIdFormat,
    },

    #[error(
        "The request for {requested} was given a production budget of {production_budget} which proved insufficient."
    )]
    ProductionBudgetInsufficient {
        requested: ResourceIdFormat,
        production_budget: ProductionBudget,
    },

    #[error(transparent)]
    EgError(Box<EgError>),
}

assert_impl_all!(ResourceProductionError: Send, Sync);

impl From<EgError> for ResourceProductionError {
    /// A [`ResourceProductionError`] can always be made from a [`EgError`].
    fn from(src: EgError) -> Self {
        match src {
            EgError::ResourceProductionError(self_) => self_,
            EgError::DuringResourceProduction(bx_egerror) => {
                ResourceProductionError::EgError(bx_egerror)
            }
            _ => ResourceProductionError::EgError(Box::new(src)),
        }
    }
}

impl From<anyhow::Error> for ResourceProductionError {
    /// A [`ResourceProductionError`] can always be made from a [`anyhow::Error`].
    #[inline]
    fn from(src: anyhow::Error) -> Self {
        EgError::from(src).into()
    }
}

impl From<std::io::Error> for ResourceProductionError {
    /// A [`ResourceProductionError`] can always be made from a [`std::io::Error`].
    #[inline]
    fn from(std_io_error: std::io::Error) -> Self {
        EgError::from(std_io_error).into()
    }
}

//=================================================================================================|

/// [`Result::Ok`](std::result::Result) type resulting from a successful [`Resource`](Resource)
/// production operation.
pub type ResourceProductionOk = (Arc<dyn Resource + 'static>, ResourceSource);

/// [`Result`](std::result::Result) type of a [`Resource`](Resource) production operation.
pub type ResourceProductionResult = Result<ResourceProductionOk, ResourceProductionError>;

//=================================================================================================|

/// An implementer of [`ResourceProducer`] should not need to implement its own caching logic.
/// It may assume that a cache has been checked before attempting to produce the object.
///
/// [`serde::Serialize`] is just needed in unit tests.
pub trait ResourceProducer: Any + std::fmt::Debug + erased_serde::Serialize + Send + Sync {
    /// Human-readable name of the [`ResourceProducer`].
    fn name(&self) -> Cow<'static, str>;

    /// The category of the [`ResourceProducer`].
    fn category(&self) -> ResourceProducerCategory {
        ResourceProducerCategory::DefaultProducer
    }

    /// Function to produce a new instance of the [`ResourceProducer`].
    fn fn_rc_new(&self) -> FnNewResourceProducer;

    //? /// The [`category`](ResourceProducerCategory) of [`ResourceProducer`].
    //fn kind(&self) -> ResourceProducerCategory;

    //? /// The priority level this [`ResourceProducer`] suggests for itself.
    //? /// Note that there is no requirement
    //? /// that this suggestion be respected.
    //? ///
    //? /// When making relative priority comparisons, the first element of the tuple is
    //? /// intended to be more significant than the [`ResourceProducerKind`] in figuring
    //? /// an effective priority, and the second is less significant.
    //? ///
    //? fn preferred_priority_pr(&self) -> (u8, u8) {
    //?     (0x80, 0x80)
    //? }

    /// Requests that the producer attempt to produce the specified data resource.
    ///
    /// The producer returns
    ///
    /// - [`None`] - If the produces does not produce this type of resource, or if it
    ///   failed for an unexceptional cause.
    /// - Some(Ok(arc, resource_source)) If it produced the resource successfully.
    /// - Some(Err(..)) - If the producer attempted to produce the resource and failed,
    ///   or other error, such as it didn't think it was even registered for this resource id.
    ///
    fn maybe_produce(&self, rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult>;
}

assert_obj_safe!(ResourceProducer);
assert_impl_all!(dyn ResourceProducer: Any, std::fmt::Debug, serde::Serialize, Send, Sync);

erased_serde::serialize_trait_object!(ResourceProducer);

//-------------------------------------------------------------------------------------------------|

/// This trait exists because of the error message:
///
/// error[E0225]: only auto traits can be used as additional traits in a trait object
/// = help: consider creating a new trait with all of these as supertraits and using that trait
/// here instead: `trait NewTrait: resource_producer::ResourceProducer + Serialize {}`
pub trait ResourceProducer_Any_Debug_Serialize:
    ResourceProducer + Any + std::fmt::Debug + erased_serde::Serialize + Send + Sync
{
}

assert_obj_safe!(ResourceProducer_Any_Debug_Serialize);
assert_impl_all!(dyn ResourceProducer_Any_Debug_Serialize:
    ResourceProducer, Any, std::fmt::Debug, serde::Serialize, Send, Sync);

erased_serde::serialize_trait_object!(ResourceProducer_Any_Debug_Serialize);

impl<T> ResourceProducer_Any_Debug_Serialize for T where
    T: ResourceProducer + Any + std::fmt::Debug + erased_serde::Serialize + Send + Sync
{
}

//=================================================================================================|

//? /// The kinds of Data Resource provider.
//? ///
//? /// These naturally form an ordered sequence appropriate for most occasions.
//? #[repr(u8)]
//? #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
//? pub enum ResourceSourceKind {
//?     /// A cache which provides access to Data Resources already loaded in memory.
//?     Cache = 0_u8,
//?
//?     /// Persistent storage.
//?     PersistentStorage = 1_u8,
//?
//?     /// Newly computed, possibly using existing sources.
//?     NewlyComputed = 2_u8,
//?
//?     /// Example data for testing.
//?     #[cfg(any(feature = "eg-allow-test-data-generation", test))]
//?     ExampleData = 3_u8,
//? }
//-------------------------------------------------------------------------------------------------|
//? bitflags! {
//?     #[repr(transparent)]
//?     #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
//?     pub struct ResourceSourceFlags: u8 {
//?         /// The Data Resource is already loaded.
//?         const ALREADY_LOADED = 1 << (ResourceSourceKind::Cache as u8);
//?
//?         /// Loaded from persistent storage.
//?         const LOAD_FROM_PERSISTENT_STORAGE = 1 << (ResourceSourceKind::PersistentStorage as u8);
//?
//?         /// Newly computed. The other flags will apply to any sources needed
//?         /// for computing and validating this object.
//?         const NEWLY_COMPUTED = 1 << (ResourceSourceKind::NewlyComputed as u8);
//?
//?         /// Example data for testing.
//?         #[cfg(any(feature = "eg-allow-test-data-generation", test))]
//?         const EXAMPLE_DATA = 1 << (ResourceSourceKind::ExampleData as u8);
//?     }
//? }
//-------------------------------------------------------------------------------------------------|
//? bitflags! {
//?     #[repr(transparent)]
//?     #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
//?     pub struct ResourceValidationFlags: u8 {
//?         /// No significant validation is performed at all.
//?         const NOT_VALIDATED = 1;
//?
//?         /// Validation that is an internal consistency check.
//?         const INTERNAL_SELF_CHECK = 1 << 1;
//?
//?         /// Validation that employs other validated sources.
//?         const EMPLOY_ALREADY_VALIDATED_SOURCES = 1 << 2;
//?     }
//? }
//-------------------------------------------------------------------------------------------------|
//? /// The allowed means of sourcing and validating the Resource.
//? #[derive(Debug)]
//? pub struct ResourceSourceReqs {
//?     /// The type(s) of data sources that are acceptable.
//?     ///
//?     /// If multiple bit flags are combined it means that any of the data sources are allowed.
//?     data_sources_allowed: ResourceSourceFlags,
//?
//?     /// The kinds of validation that are acceptable.
//?     /// If multiple bit flags are combined it means that it is requred to do at least one of them.
//?     ///
//?     /// It would be pointless to set this to [`ResourceValidationFlags::EMPTY`], which would imply that the object cannot be used.
//?     ///
//?     validation_kinds_allowed: ResourceValidationFlags,
//? }
//-------------------------------------------------------------------------------------------------|
