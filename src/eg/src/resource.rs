// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::any::Any;
use std::{borrow::Cow, pin::Pin};
//use std::collections::HashSet;
//use std::io::{BufRead, Cursor};
//use std::path::{Path, PathBuf};
use std::sync::Arc;

//use std::str::FromStr;
//use std::sync::OnceLock;

//use anyhow::{anyhow, bail, ensure, Context, Result};
use downcast_rs::DowncastSync;
use futures_lite::FutureExt;
use tracing::Instrument;
//use either::Either;
use tracing::{
    debug, debug_span, error, field::display as trace_display, info, info_span, instrument, trace,
    trace_span, warn,
};
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};
//use rand::{distr::Uniform, Rng, RngCore};
use serde::{Deserialize, Serialize};
use static_assertions::{assert_impl_all, assert_obj_safe}; // assert_cfg, const_assert
use util::{abbreviation::Abbreviation, vec1::Vec1};

use crate::errors::ResourceProductionError;
use crate::guardian::{AsymmetricKeyPart, GuardianIndex};
use crate::guardian_public_key::GuardianPublicKey;
/// Re-export [`ResourceId`] and related names because they're so essential.
pub use crate::resource_id::{ElectionDataObjectId, ResourceFormat, ResourceId, ResourceIdFormat};
use crate::resource_producer::ResourceSource;
use crate::{
    eg::Eg,
    errors::{EgError, EgResult},
    guardian::{GuardianKeyPartId, GuardianKeyPurpose},
    resource_path::ResourceNamespacePath,
    resource_producer::ResourceProductionResult,
    serializable::{SerializableCanonical, SerializablePretty},
    validatable::{MayBeValidatableUnsized, ValidatableUnsized, ValidatedUnsized},
};

//=================================================================================================|

/// A [`Resource`] is info available to processing.
///
/// Typically variants correspond to file paths, most commonly a serialized representation of
/// an [`ElectionDataObject`].
///
/// Often it is a temporary used create an [`ElectionDataObject`] through [validation](
/// crate::validatableValidated), but they can be other data se well.
///
/// For example, an `ElectionDataObject` type may be serialized to a file, but may not be
/// [deserialized](serde::Deserialize) directly. Instead, the corresponding `Resource` is
/// loaded, and the `ElectionDataObject` created through validation.
///
pub trait Resource:
    DowncastSync
    + std::fmt::Debug
    + erased_serde::Serialize
    + SerializableCanonical
    + AsSerializableCanonical
    + SerializablePretty //+ MayBeValidatableUnsized
{
    /// Returns the [`ResourceIdFormat`] of this resource.
    fn ridfmt(&self) -> &ResourceIdFormat;

    /// Returns the [`ResourceId`] of this resource.
    fn rid(&self) -> &ResourceId {
        &self.ridfmt().rid
    }

    /// Returns the [`ResourceFormat`] of this resource.
    fn format(&self) -> &ResourceFormat {
        &self.ridfmt().fmt
    }

    /// Returns the [`ElectionDataObjectId`] of this resource, if it happens to represent
    /// an [`ElectionDataObject`].
    fn edoid_opt(&self) -> Option<&ElectionDataObjectId> {
        use ResourceId::*;
        match self.rid() {
            ElectionDataObject(edoid) => Some(edoid),
            _ => None,
        }
    }

    /// Returns the resource as a slice of bytes, perhaps suitable for deserialization.
    fn as_slice_bytes(&self) -> Option<&[u8]> {
        None
    }

    /*
    /// Returns the [`std::io::Read`], if the resource supports it.
    /// This should be buffered under the hood.
    fn as_stdio_read_opt(&mut self) -> Option<&dyn std::io::Read> {
        None
    }
    // */
}

downcast_rs::impl_downcast!(sync Resource); //? concrete

erased_serde::serialize_trait_object!(Resource);

//=================================================================================================|

/// Trait for types that can return a ref to a static ResourceIdFormat.
pub trait HasStaticResourceIdFormat
//    DowncastSync
//+ std::fmt::Debug
//+ erased_serde::Serialize
//+ SerializableCanonical + SerializablePretty
{
    fn static_ridfmt(&self) -> &'static ResourceIdFormat;
}

impl<T> Resource for T
where
    T: HasStaticResourceIdFormat
        + DowncastSync
        + std::fmt::Debug
        + erased_serde::Serialize
        + SerializableCanonical
        + AsSerializableCanonical
        + SerializablePretty, //+ MayBeValidatableUnsized,
{
    fn ridfmt(&self) -> &ResourceIdFormat {
        Self::static_ridfmt(self)
    }
}

//=================================================================================================|

/// Trait for types that could possibly implement the [`Resource`] trait.
pub trait MayBeResource {
    /// May return [`&self`](self) as a [`&dyn Resource`](Resource).
    fn opt_as_resource(&self) -> Option<&dyn Resource>;

    /// May return [`&mut self`](self) as a [`&mut dyn Resource`](Resource).
    fn opt_as_resource_mut(&mut self) -> Option<&mut dyn Resource>;
}

impl<T> MayBeResource for T
where
    T: Resource,
{
    fn opt_as_resource(&self) -> Option<&dyn Resource> {
        Some(self)
    }

    fn opt_as_resource_mut(&mut self) -> Option<&mut dyn Resource> {
        Some(self)
    }
}

//=================================================================================================|

/// Trait for types that could possibly implement the [`Resource`] trait.
pub trait AsSerializableCanonical {
    /// Returns the [`SerializableCanonical`] trait.
    fn as_dyn_serializable_canonical(&self) -> &dyn SerializableCanonical;
}

impl<T> AsSerializableCanonical for T
where
    T: SerializableCanonical + Sized,
{
    fn as_dyn_serializable_canonical(&self) -> &dyn SerializableCanonical {
        self
    }
}

//=================================================================================================|

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    strum_macros::Display
)]
pub enum ProductionBudget {
    #[strum(to_string = "zero")]
    Zero,

    #[strum(to_string = "unlimited")]
    Unlimited,
}

//=================================================================================================|

/// Trait implemented by types that handle requests for the production of Resources.
///
/// Generally, you would call a method on [`ProduceResourceExt`] instead.
pub trait ProduceResource: Send + Sync + 'static {
    /// Provides access to the [`Csrng`].
    fn csrng(&self) -> &dyn util::csrng::Csrng;

    /// Implement this, but call [`ProduceResourceExt::produce_resource()`].
    fn trait_impl_produce_resource_<'a>(
        &'a self,
        ridfmt: ResourceIdFormat,
        opt_prod_budget: Option<ProductionBudget>,
    ) -> Pin<Box<dyn Future<Output = ResourceProductionResult> + Send + 'a>>;
}

assert_obj_safe!(ProduceResource);
assert_impl_all!(dyn ProduceResource: Send, Sync);

//-------------------------------------------------------------------------------------------------|

macro_rules! helper_method_validated_edo_type {
    { $method_name:ident, $edoid:ident, $concrete_dr_type:path } => {
        /// Convenience method to obtain a [`ElectionDataObjectId::$edoid:ident`].
        fn $method_name<'a>(&'a self) ->
            Pin<Box<dyn Future<Output = EgResult<Arc<$concrete_dr_type>>> + Send + 'a>>
        {
            let ridfmt = crate::resource::ElectionDataObjectId::$edoid.validated_type_ridfmt();
            async move {
                self.produce_resource_downcast_no_src::<$concrete_dr_type>(&ridfmt)
                .await
                .map_err(Into::into)
            }.boxed()
        }
    };
}

/// Trait for requesting the production of Resources.
pub trait ProduceResourceExt: ProduceResource + Send + Sync + 'static {
    /// Attempts to produce the requested resource.
    fn produce_resource<'a>(
        &'a self,
        ridfmt: &ResourceIdFormat,
    ) -> Pin<Box<dyn Future<Output = ResourceProductionResult> + Send + 'a>> {
        self.produce_resource_budget(ridfmt, None)
    }

    /// Attempts to produce the requested resource.
    fn produce_resource_budget<'a>(
        &'a self,
        ridfmt: &ResourceIdFormat,
        opt_prod_budget: Option<ProductionBudget>,
    ) -> Pin<Box<dyn Future<Output = ResourceProductionResult> + Send + 'a>> {
        let span = debug_span!(
            "produce",
            rf = tracing::field::display(ridfmt.abbreviation())
        );
        self.trait_impl_produce_resource_(ridfmt.clone(), opt_prod_budget)
            .instrument(span)
            .boxed()
    }

    /// Attempts to produce the requested resource.
    /// Returns just the Arc<dyn Resource>, to simplify the many cases where the caller isn't
    /// interested in the [`ResourceSource`].
    fn produce_resource_no_src<'a>(
        &'a self,
        ridfmt: &ResourceIdFormat,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn Resource>, ResourceProductionError>> + Send + 'a>>
    {
        self.produce_resource_budget_no_src(ridfmt, None)
    }

    /// Attempts to produce the requested resource.
    /// Returns just the Arc<dyn Resource>, to simplify the many cases where the caller isn't
    /// interested in the [`ResourceSource`].
    fn produce_resource_budget_no_src<'a>(
        &'a self,
        ridfmt: &ResourceIdFormat,
        opt_prod_budget: Option<ProductionBudget>,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn Resource>, ResourceProductionError>> + Send + 'a>>
    {
        let span = debug_span!(
            "produce",
            rf = tracing::field::display(ridfmt.abbreviation())
        );
        let ridfmt = ridfmt.clone();
        let pbxf = self.trait_impl_produce_resource_(ridfmt, opt_prod_budget);
        async move { pbxf.await.map(|(arc, _)| arc) }
            .instrument(span)
            .boxed()
    }

    /// Attempts to produce the requested resource and downcast it as the specified type.
    /// Returns the `Arc<T>`.
    fn produce_resource_downcast<'a, T: Resource + Any + 'static>(
        &'a self,
        ridfmt: &ResourceIdFormat,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(Arc<T>, ResourceSource), ResourceProductionError>>
                + Send
                + 'a,
        >,
    > {
        self.produce_resource_budget_downcast::<T>(ridfmt, None)
    }

    /// Attempts to produce the requested resource and downcast it as the specified type.
    /// Returns the `Arc<T>`.
    fn produce_resource_budget_downcast<'a, T: Resource + Any + 'static>(
        &'a self,
        ridfmt: &ResourceIdFormat,
        opt_prod_budget: Option<ProductionBudget>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(Arc<T>, ResourceSource), ResourceProductionError>>
                + Send
                + 'a,
        >,
    > {
        let span = debug_span!(
            "produce",
            rf = tracing::field::display(ridfmt.abbreviation())
        );
        let ridfmt = ridfmt.clone();
        let pbxf = self.trait_impl_produce_resource_(ridfmt.clone(), opt_prod_budget);
        async move {
            let (arc_dyn_resource, resource_source) = pbxf.await?;

            let src_typename = std::any::type_name_of_val(arc_dyn_resource.as_ref());
            let src_typeid = arc_dyn_resource.as_ref().type_id();

            let arc_dyn_any_send_sync = arc_dyn_resource.into_any_arc();

            match arc_dyn_any_send_sync.downcast::<T>() {
                Err(arc) => {
                    let src_type_expected = format!(
                        "{} {:?}",
                        std::any::type_name::<T>(),
                        std::any::TypeId::of::<T>()
                    );
                    let src_type_expected2 = src_type_expected.clone();
                    let e = ResourceProductionError::CouldntDowncastResource {
                        src_ridfmt: ridfmt.clone(),
                        src_resource_source: resource_source,
                        src_type: format!("{} {:?}", src_typename, src_typeid),
                        opt_src_type_expected: Some(src_type_expected),
                        target_type: src_type_expected2,
                    };
                    error!("resource: {e:?}");
                    Err(e)
                }
                Ok(arc) => {
                    let src_type_expected = format!(
                        "{} {:?}",
                        std::any::type_name::<T>(),
                        std::any::TypeId::of::<T>()
                    );
                    debug!("SuccessfullyDowncastResource {{ src_ridfmt: {}, src_resource_source: {resource_source}, src_type: {} }}",
                        ridfmt.clone(), format!("{} {:?}", src_typename, src_typeid));

                    Ok((arc, resource_source))
                },
            }
        }
        .instrument(span)
        .boxed()
    }

    /// Attempts to produce the requested resource and downcast it as the specified type.
    ///
    /// Returns just the `Arc<T>` without [source information](ResourceSource).
    fn produce_resource_budget_downcast_no_src<'a, T: Resource + Any + 'static>(
        &'a self,
        ridfmt: &ResourceIdFormat,
        opt_prod_budget: Option<ProductionBudget>,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<T>, ResourceProductionError>> + Send + 'a>> {
        let pbxf = self.produce_resource_budget_downcast::<T>(ridfmt, opt_prod_budget);
        async move { pbxf.await.map(|(arc, _)| arc) }.boxed()
    }

    /// Attempts to produce the requested resource and downcast it as the specified type.
    ///
    /// Returns just the `Arc<T>` without [source information](ResourceSource).
    fn produce_resource_downcast_no_src<'a, T: Resource + Any + 'static>(
        &'a self,
        ridfmt: &ResourceIdFormat,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<T>, ResourceProductionError>> + Send + 'a>> {
        self.produce_resource_budget_downcast_no_src::<T>(ridfmt, None)
    }

    helper_method_validated_edo_type!(
        fixed_parameters,
        FixedParameters,
        crate::fixed_parameters::FixedParameters
    );
    helper_method_validated_edo_type!(
        varying_parameters,
        VaryingParameters,
        crate::varying_parameters::VaryingParameters
    );
    helper_method_validated_edo_type!(
        election_parameters,
        ElectionParameters,
        crate::election_parameters::ElectionParameters
    );
    helper_method_validated_edo_type!(
        election_manifest,
        ElectionManifest,
        crate::election_manifest::ElectionManifest
    );
    helper_method_validated_edo_type!(hashes, Hashes, crate::hashes::Hashes);
    //? todo helper_method_validated_edo_type!(guardian_key_part, GuardianKeyPart(GuardianKeyId),

    //? TODO #[cfg(any(feature = "eg-allow-test-data-generation", test))] GeneratedTestDataVoterSelections(crate::hash::HValue),

    //? TODO   Ballot ?

    /// Provides the guardian public keys for the specified purpose.
    ///
    /// If any key part fails to load, the entire function returns `Err`.
    #[allow(async_fn_in_trait)]
    async fn guardian_public_keys(
        &self,
        key_purpose: GuardianKeyPurpose,
    ) -> EgResult<Vec1<Arc<GuardianPublicKey>>> {
        use crate::resource_id::ElectionDataObjectId as EdoId;

        let varying_parameters = self.varying_parameters().await?;
        let varying_parameters = varying_parameters.as_ref();

        let n: GuardianIndex = varying_parameters.n();

        let mut v1 = Vec1::with_capacity(n.into());
        for guardian_ix in GuardianIndex::iter_range_inclusive(GuardianIndex::one(), n) {
            let guardian_key_id = GuardianKeyPartId {
                guardian_ix,
                key_purpose,
                asymmetric_key_part: AsymmetricKeyPart::Public,
            };
            let edoid = EdoId::GuardianKeyPart(guardian_key_id);
            let ridfmt = edoid.validated_type_ridfmt();
            let public_key = self
                .produce_resource_downcast_no_src::<GuardianPublicKey>(&ridfmt)
                .await
                .map_err(Into::<EgError>::into)?;
            v1.try_push(public_key)?;
        }

        Ok(v1)
    }

    /// Convenience method to obtain the "joint vote encryption public key K".
    #[allow(async_fn_in_trait)]
    async fn joint_vote_encryption_public_key_k(
        &self,
    ) -> EgResult<Arc<crate::joint_public_key::JointPublicKey>> {
        self.joint_public_key(
            GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
        )
        .await
    }

    /// Convenience method to obtain the "joint ballot data encryption public key ̂K" (K hat).
    #[allow(async_fn_in_trait)]
    async fn joint_ballot_data_encryption_public_key_k_hat(
        &self,
    ) -> EgResult<Arc<crate::joint_public_key::JointPublicKey>> {
        self.joint_public_key(GuardianKeyPurpose::Encrypt_Ballot_AdditionalFreeFormData)
            .await
    }

    /// Convenience method to obtain a [`JointPublicKey`] for the specified key purpose.
    ///
    /// Prefer to use [`joint_vote_encryption_public_key_k`] or
    /// [`joint_ballot_data_encryption_public_key_k_hat`] where possible.
    #[allow(async_fn_in_trait)]
    async fn joint_public_key(
        &self,
        key_purpose: GuardianKeyPurpose,
    ) -> EgResult<Arc<crate::joint_public_key::JointPublicKey>> {
        use crate::resource_id::ElectionDataObjectId as EdoId;

        if !key_purpose.forms_joint_public_key() {
            return Err(EgError::NoJointPublicKeyForPurpose { key_purpose });
        }

        let ridfmt = EdoId::JointPublicKey(key_purpose).validated_type_ridfmt();

        let arc_jpk = self
            .produce_resource_downcast_no_src::<crate::joint_public_key::JointPublicKey>(&ridfmt)
            .await?;
        Ok(arc_jpk)
    }

    helper_method_validated_edo_type!(
        extended_base_hash,
        ExtendedBaseHash,
        crate::extended_base_hash::ExtendedBaseHash
    );

    helper_method_validated_edo_type!(
        pre_voting_data,
        PreVotingData,
        crate::pre_voting_data::PreVotingData
    );

    /// Provides the guardian secret keys for the specified purpose.
    /// (Only available with feature `eg-allow-test-data-generation` or `cfg(test)`, and even
    /// then there is no guarantee this data will be accessible to the caller.)
    ///
    /// If any key part fails to load, the entire function returns `Err`.
    #[cfg(any(feature = "eg-allow-test-data-generation", test))]
    #[allow(async_fn_in_trait)]
    async fn guardians_secret_keys(
        &self,
        key_purpose: GuardianKeyPurpose,
    ) -> EgResult<Vec1<Arc<crate::guardian_secret_key::GuardianSecretKey>>> {
        use crate::resource_id::ElectionDataObjectId as EdoId;

        let varying_parameters = self.varying_parameters().await?;
        let varying_parameters = varying_parameters.as_ref();

        let n: GuardianIndex = varying_parameters.n();

        let mut v1 = Vec1::with_capacity(n.into());
        for guardian_ix in GuardianIndex::iter_range_inclusive(GuardianIndex::one(), n) {
            let guardian_key_id = GuardianKeyPartId {
                guardian_ix,
                key_purpose,
                asymmetric_key_part: AsymmetricKeyPart::Secret,
            };
            let edoid = EdoId::GuardianKeyPart(guardian_key_id);
            let ridfmt = edoid.validated_type_ridfmt();
            let secret_key = self
                .produce_resource_downcast_no_src::<crate::guardian_secret_key::GuardianSecretKey>(
                    &ridfmt,
                )
                .await
                .map_err(Into::<EgError>::into)?;
            v1.try_push(secret_key)?;
        }

        Ok(v1)
    }
}

impl<T> ProduceResourceExt for T where T: ProduceResource + Send + Sync + ?Sized + 'static {}
//impl<T> ProduceResourceExt for T where
//    T: dyn ProduceResource
//{}

//assert_impl_all!(ProduceResourceExt: Send, Sync);

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{Context, Result, anyhow, bail, ensure};
    use insta::assert_ron_snapshot;

    use super::*;
    use crate::guardian::{AsymmetricKeyPart, GuardianIndex, GuardianKeyPurpose};

    #[test_log::test]
    fn edoid() {
        use ElectionDataObjectId::*;
        use GuardianKeyPurpose::*;
        assert_ron_snapshot!(FixedParameters, @"FixedParameters");
        assert_ron_snapshot!(VaryingParameters, @"VaryingParameters");
        assert_ron_snapshot!(ElectionParameters, @"ElectionParameters");
        assert_ron_snapshot!(ElectionManifest, @"ElectionManifest");
        assert_ron_snapshot!(Hashes, @"Hashes");
        assert_ron_snapshot!(GuardianKeyPart(GuardianKeyPartId {
            guardian_ix: GuardianIndex::one(),
            key_purpose: Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
            asymmetric_key_part: AsymmetricKeyPart::Secret,
        }), @r#"
        GuardianKeyPart(GuardianKeyPartId(
          guardian_ix: 1,
          key_purpose: Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
          asymmetric_key_part: Secret,
        ))
        "#);
        assert_ron_snapshot!(JointPublicKey(Encrypt_Ballot_AdditionalFreeFormData), @"JointPublicKey(Encrypt_Ballot_AdditionalFreeFormData)");
        assert_ron_snapshot!(ExtendedBaseHash, @"ExtendedBaseHash");
        assert_ron_snapshot!(PreVotingData, @"PreVotingData");

        #[cfg(feature = "eg-allow-test-data-generation")]
        assert_ron_snapshot!(GeneratedTestDataVoterSelections(
            crate::hash::HValue::from(std::array::from_fn(|ix| ix as u8 + 0x70))
        ), @r#"GeneratedTestDataVoterSelections("707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F")"#);
    }

    #[test_log::test]
    fn rid() {
        use ElectionDataObjectId::*;
        use ResourceId::*;

        assert_ron_snapshot!(
            ElectionGuardDesignSpecificationVersion,
            @"ElectionGuardDesignSpecificationVersion");

        assert_ron_snapshot!(
            ElectionDataObject(FixedParameters),
            @"ElectionDataObject(FixedParameters)");

        assert_ron_snapshot!(ElectionDataObject(FixedParameters).try_figure_namespace_path(), @"None");
    }
}
