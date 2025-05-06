// Copyright (C) Microsoft Corporation. All rights reserved.

//! Macros for implementing [`Resource`](crate::resource::Resource) and
//! [`Validatable`](crate::validatable::Validatable) and other traits.

/// Implements [`KnowsFriendlyTypeName`](crate::loadable::KnowsFriendlyTypeName).
#[macro_export]
macro_rules! impl_knows_friendly_type_name {
    { $src:ident } => {
        impl $crate::loadable::KnowsFriendlyTypeName for $src {
            fn friendly_type_name() -> std::borrow::Cow<'static, str> {
                std::stringify!($src).into()
            }
        }
    };
}

/// Implements [`MayBeValidatableUnsized`](crate::validatable::MayBeValidatableUnsized) for types that do not
/// implement [`ValidatableUnsized`](crate::validatable::ValidatableUnsized) (which has a blanket implementation).
#[macro_export]
macro_rules! impl_MayBeValidatableUnsized_for_non_ValidatableUnsized {
    { $src:ident } => {
        impl $crate::validatable::MayBeValidatableUnsized for $src {
            fn opt_as_validatableunsized(&self) -> Option<&dyn $crate::validatable::ValidatableUnsized> {
                None
            }
        }
    };
}

/// Implements [`MayBeResource`](crate::resource::MayBeResource) for types that do not
/// implement [`Resource`](crate::resource::Resource) (which has a blanket implementation).
#[macro_export]
macro_rules! impl_MayBeResource_for_non_Resource {
    { $src:ident } => {
        impl $crate::resource::MayBeResource for $src {
            fn opt_as_resource(&self) -> Option<&dyn $crate::resource::Resource> {
                None
            }
            fn opt_as_resource_mut(&mut self) -> Option<&mut dyn $crate::resource::Resource> {
                None
            }
        }
    };
}

#[macro_export]
macro_rules! impl_Resource_for_simple_ResourceId_type {
    { $resource_type:path, $resource_id:ident, $resource_fmt:ident } => {
        impl $crate::resource::HasStaticResourceIdFormat for $resource_type {
            fn static_ridfmt(&self) -> &'static $crate::resource::ResourceIdFormat {
                static RIDFMT: $crate::resource::ResourceIdFormat = $crate::resource::ResourceIdFormat {
                    rid: $crate::resource::ResourceId::$resource_id,
                    fmt: $crate::resource::ResourceFormat::$resource_fmt,
                };
                &RIDFMT
            }
        }
    };
}

#[macro_export]
macro_rules! impl_Resource_for_simple_ElectionDataObjectId_type {
    { $concrete_dr_type:path, $edoid:ident, $memfn:ident } => {
        impl $crate::resource::HasStaticResourceIdFormat for $concrete_dr_type {
            fn static_ridfmt(&self) -> &'static $crate::resource::ResourceIdFormat {
                static RIDFMT: $crate::resource::ResourceIdFormat =
                $crate::resource::ElectionDataObjectId::$edoid.$memfn();
                &RIDFMT
            }
        }
    };
}

/// Implements [`Resource`](crate::resource::Resource) for
/// [`Validatable`](crate::validatable::Validatable) but non-[`Validated`](crate::validatable::Validated)
/// "Info" types having simple
/// [`ResourceId`s](crate::resource::ResourceId) which
/// implement [`HasStaticResourceIdFormat`](crate::resource::HasStaticResourceIdFormat)
#[macro_export]
macro_rules! impl_Resource_for_simple_ElectionDataObjectId_info_type {
    { $concrete_dr_type:path, $edoid:ident } => {
        $crate::impl_Resource_for_simple_ElectionDataObjectId_type! { $concrete_dr_type, $edoid, info_type_ridfmt }
    };
}

/// Implements [`Resource`](crate::resource::Resource) for
/// [`Validated`](crate::validatable::Validated) (non "Info") types having simple
/// [`ResourceId`s](crate::resource::ResourceId) which
/// implement [`HasStaticResourceIdFormat`](crate::resource::HasStaticResourceIdFormat)
#[macro_export]
macro_rules! impl_Resource_for_simple_ElectionDataObjectId_validated_type {
    { $concrete_dr_type:path, $edoid:ident } => {
        $crate::impl_Resource_for_simple_ElectionDataObjectId_type! { $concrete_dr_type, $edoid, validated_type_ridfmt }
    };
}

/// Implements [`Validatable`](crate::validatable::Validatable) and
/// [`Validated`](crate::validatable::Validated).
///
/// This macro encloses the function body which attempts to converts the `src` type to the
/// validated type or return a validation error.
///
/// See examples for use.
#[macro_export]
macro_rules! impl_validatable_validated {
    // No version specifier implies version 1
    { $src:ident : $t_validatable:path, $eg:ident => EgResult< $t_validated:path > { $( $guts:tt )* } } => {
        $crate::impl_validatable_validated! {
            version_1 : $src : $t_validatable, $eg => EgResult< $t_validated > { $( $guts )* } }
    };

    // Version 1 specified
    { version_1 : $src:ident : $t_validatable:path, $eg:ident => EgResult< $t_validated:path > { $( $guts:tt )* } } => {
        $crate::impl_validatable_validated! {
            @common_version_1_2 : $src : $t_validatable, $eg => EgResult< $t_validated > { $( $guts )* } }

        #[async_trait::async_trait(?Send)]
        impl $crate::validatable::Validated for $t_validated {
            type ValidatedFrom = $t_validatable;

            /*#[allow(unused_variables)]
            #[allow(unused_imports)]
            async fn try_validate_from_async(
                $src: Self::ValidatedFrom,
                $eg: & $crate::eg::Eg,
            ) -> $crate::errors::EgResult<$t_validated> {
                static SPAN_NAME: &str = std::concat!(std::stringify!($t_validated), "::try_validate_from_async");
                let span = tracing::trace_span!(SPAN_NAME);
                let _enter_span = span.enter();

                Self::try_validate_from_async_impl_($src, $eg).await
            }

            #[allow(unused_variables)]
            #[allow(unused_imports)]
            fn try_validate_from(
                $src: Self::ValidatedFrom,
                $eg: & $crate::eg::Eg,
            ) -> $crate::errors::EgResult<$t_validated> {
                static SPAN_NAME: &str = std::concat!(std::stringify!($t_validated), "::try_validate_from");
                let span = tracing::trace_span!(SPAN_NAME);
                let _enter_span = span.enter();

                async_global_executor::block_on(Self::try_validate_from_async_impl_($src, $eg))
            }
            // */

            #[allow(unused_variables)]
            #[allow(unused_imports)]
            async fn try_validate_from_async_impl_(
                $eg: &(dyn $crate::resource::ProduceResource + Send + Sync + 'static),
                $src: Self::ValidatedFrom,
            ) -> $crate::errors::EgResult<$t_validated> {
                use $crate::{
                    resource::{ProduceResource,ProduceResourceExt},
                    validatable::*
                };
                $( $guts )*
            }
        }
    };

    // Version 2 specified
    { version_2: $src:ident : $t_validatable:path, $eg:ident => EgResult< $t_validated:path > { $( $guts:tt )* } } => {
        $crate::impl_validatable_validated! {
            @common_version_1_2 : $src : $t_validatable, $eg => EgResult< $t_validated > { $( $guts )* } }

        #[async_trait::async_trait(?Send)]
        impl $crate::validatable::Validated for $t_validated {
            type ValidatedFrom = $t_validatable;

            /*
            #[allow(unused_variables)]
            #[allow(unused_imports)]
            async fn try_validate_from_async(
                $src: Self::ValidatedFrom,
                $eg: & $crate::eg::Eg,
            ) -> $crate::errors::EgResult<$t_validated> {
                static SPAN_NAME: &str = std::concat!(std::stringify!($t_validated), "::try_validate_from_async");
                let span = tracing::trace_span!(SPAN_NAME);
                let _enter_span = span.enter();

                use $crate::validatable::*;
                $( $guts )*
            }
            // */

            #[allow(unused_variables)]
            #[allow(unused_imports)]
            async fn try_validate_from_async_impl_(
                $eg: &(dyn $crate::resource::ProduceResource + Send + Sync + 'static),
                $src: Self::ValidatedFrom,
            ) -> $crate::errors::EgResult<$t_validated> {
                use $crate::{
                    resource::{ProduceResource,ProduceResourceExt},
                    validatable::*
                };
                $( $guts )*
            }
        }
    };

    { @common_version_1_2 : $src:ident : $t_validatable:path, $eg:ident => EgResult< $t_validated:path > { $( $guts:tt )* } } => {
        #[async_trait::async_trait(?Send)]
        /*
        impl $crate::validatable::ValidatableUnsized for $t_validatable {
            async fn arc_validate_into_rc(
                self: std::sync::Arc<Self>,
                $eg: & $crate::eg::Eg,
            ) -> $crate::errors::EgResult<std::sync::Arc<dyn $crate::validatable::ValidatedUnsized>> {
                use std::sync::Arc;

                static SPAN_NAME: &str = std::concat!(std::stringify!($t_validated), "::arc_validate_into_rc");
                let span = tracing::trace_span!(SPAN_NAME);
                let _enter_span = span.enter();

                let src = Arc::unwrap_or_clone(self);
                let validated = <$t_validated as $crate::validatable::Validated>::try_validate_from_async_impl_(src, $eg).await?;
                let arc_dyn: Arc::<dyn $crate::validatable::ValidatedUnsized + '_> = Arc::new(validated);
                Ok(arc_dyn)
            }
        }

        /*
        impl $crate::validatable::MayBeValidatableUnsized for $t_validatable {
            fn opt_as_validatableunsized(&self) -> Option<&dyn $crate::validatable::ValidatableUnsized> {
                Some(self)
            }
        }
        // */

        impl $crate::validatable::ValidatedUnsized for $t_validated  {
        }

        impl $crate::validatable::MayBeValidatableUnsized for $t_validated {
            fn opt_as_validatableunsized(&self) -> Option<&dyn $crate::validatable::ValidatableUnsized> {
                None
            }
        }
        // */

        impl $crate::validatable::Validatable for $t_validatable {
            type ValidatedInto = $t_validated;
        }

        impl $crate::validatable::Validatable for $t_validated {
            type ValidatedInto = $t_validated;
        }
    };

    /*
    /// Use this form when `Validatable` (_info) type implements HasStaticResourceIdFormat and Resource.
    ///
    /// It will register resource creation
    {
        $gather_rpspecific_registrations_fn:ident,
        $resource_id:expr,
        $src:ident : $t_validatable:path, $eg:ident => EgResult< $t_validated:path > { $( $guts:tt )* }
    } => {
        $crate::impl_validatable_validated! {
            $src : $t_validatable, $eg => EgResult<$t_validated>
        }

        fn $gather_rpspecific_registrations_fn(
            register_fn: &mut dyn FnMut($crate::resource_producer_registry::RPFnRegistration)
        ) {
            use $crate::{
                eg::Eg,
                resource::{Resource, ResourceFormat, ResourceId, ResourceIdFormat},
                resource_producer::{
                    ResourceProductionError,
                    ResourceProducer,
                    ResourceProductionResult, ResourceSource,
                    ResourceProducer_Any_Debug_Serialize,
                },
                resourceproducer_specific::{
                    GatherRPFnRegistrationsFnWrapper,
                },
                resource_producer_registry::{
                    FnNewResourceProducer,
                    GatherResourceProducerRegistrationsFnWrapper,
                    ResourceProducerCategory,
                    ResourceProducerRegistration,
                    ResourceProducerRegistry,
                    RPFnRegistration,
                },
                resource_production::RpOp,
                resource_slicebytes::ResourceSliceBytes,
            };

            #[allow(non_snake_case)]
            fn maybe_produce_ConcreteType(rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
                let ridfmt_expected = ResourceIdFormat {
                    rid: $resource_id,
                    fmt: ResourceFormat::ConcreteType,
                };

                let ridfmt_requested = rp_op.target_ridfmt();

                if rp_op.target_ridfmt() != &ridfmt_expected {
                    return Some(Err(ResourceProductionError::UnexpectedResourceIdFormatRequested {
                        ridfmt_expected,
                        ridfmt_requested: ridfmt_requested.into_owned(),
                    }));
                }

                let arc: Arc<dyn Resource> = Arc::new(crate::EGDS_VERSION);
                let rpsrc = ResourceSource::constructed_concretetype();
                let result: ResourceProductionResult = Ok((arc, rpsrc));
                Some(result)
            }
            register_fn(RPFnRegistration::new_defaultproducer(
                ResourceIdFormat {
                    rid: ResourceId::ElectionGuardDesignSpecificationVersion,
                    fmt: ResourceFormat::ConcreteType,
                },
                Box::new(maybe_produce_ElectionGuardDesignSpecificationVersion_ConcreteType) )
            );


            f(&[crate::resource_producer_registry::ResourceProducerRegistration::new_defaultproducer(
                stringify!($t_validatable),
                ||,
            )]);
        }

        inventory::submit! {
            GatherRPFnRegistrationsFnWrapper($gather_rpspecific_registrations_fn)
        }
    };
    // */
}
