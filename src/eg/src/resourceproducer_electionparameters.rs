// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(clippy::let_and_return)] //? TODO: Remove temp development code
#![allow(clippy::needless_lifetimes)] //? TODO: Remove temp development code
#![allow(dead_code)] //? TODO: Remove temp development code
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

#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    borrow::{
        Cow,
        //Borrow,
    },
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //hash::{BuildHasher, Hash, Hasher},
    //io::{BufRead, Cursor},
    //iter::zip,
    //marker::PhantomData,
    //path::{Path, PathBuf},
    //process::ExitCode,
    sync::Arc,
    //str::FromStr,
    //sync::{
        //Arc,
        //OnceLock,
    //},
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
use either::Either;
//use futures_lite::future::{self, FutureExt};
//use hashbrown::HashMap;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use util::abbreviation::Abbreviation;

use crate::{
    eg::Eg,
    election_parameters::{ElectionParameters, ElectionParametersInfo},
    errors::ResourceProductionError,
    fixed_parameters::{
        FixedParameters, FixedParametersInfo, FixedParametersTrait, FixedParametersTraitExt,
    },
    loadable::KnowsFriendlyTypeName,
    resource::{
        ElectionDataObjectId as EdoId, HasStaticResourceIdFormat, ProduceResource,
        ProduceResourceExt, Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionOk,
        ResourceProductionResult, ResourceSource,
    },
    resource_producer_registry::{
        FnNewResourceProducer, GatherResourceProducerRegistrationsFnWrapper, RPFnRegistration,
        ResourceProducerCategory, ResourceProducerRegistration, ResourceProducerRegistry,
    },
    resource_production::RpOp,
    resourceproducer_specific::GatherRPFnRegistrationsFnWrapper,
    validatable::{Validatable, Validated},
    varying_parameters::{VaryingParameters, VaryingParametersInfo},
};

//=================================================================================================|

#[allow(non_upper_case_globals)]
const RID_ElectionParameters: ResourceId =
    ResourceId::ElectionDataObject(EdoId::ElectionParameters);

#[allow(non_upper_case_globals)]
const RIDFMT_ElectionParameters_ConcreteType: ResourceIdFormat = ResourceIdFormat {
    rid: RID_ElectionParameters,
    fmt: ResourceFormat::ConcreteType,
};

#[allow(non_upper_case_globals)]
const RIDFMT_ElectionParameters_ValidatedEdo: ResourceIdFormat = ResourceIdFormat {
    rid: RID_ElectionParameters,
    fmt: ResourceFormat::ValidElectionDataObject,
};

#[allow(non_snake_case)]
fn maybe_produce_ElectionParameters_ConcreteType(
    rp_op: &Arc<RpOp>,
) -> Option<ResourceProductionResult> {
    async_global_executor::block_on(maybe_produce_ElectionParameters_ConcreteType_async(rp_op))
}

#[allow(non_snake_case)]
async fn maybe_produce_ElectionParameters_ConcreteType_async(
    rp_op: &Arc<RpOp>,
) -> Option<ResourceProductionResult> {
    // Only handle ElectionParametersInfo in the ConcreteType format.
    let mut ridfmt = RIDFMT_ElectionParameters_ConcreteType;

    let ridfmt_requested = rp_op.requested_ridfmt();

    if ridfmt_requested.as_ref() != &ridfmt {
        return Some(Err(
            ResourceProductionError::UnexpectedResourceIdFormatRequested {
                ridfmt_expected: ridfmt,
                ridfmt_requested: ridfmt_requested.into_owned(),
            },
        ));
    }

    // If we already have a Validated EDO in the cache, just unvalidate it.
    let ridfmt = RIDFMT_ElectionParameters_ValidatedEdo;
    if let Some(Ok((arc_election_parameters, produce_resource))) = rp_op
        .resources()
        .obtain_resource_production_result_from_cache_downcast::<ElectionParameters>(&ridfmt)
        .await
    {
        // Un-validate the ElectionParameters back to an ElectionParametersInfo
        let produce_resource = ResourceSource::un_validated_from(produce_resource);
        let election_parameters_info =
            <ElectionParameters as Validated>::un_validate_from_rc(arc_election_parameters);
        let production_result_ok: ResourceProductionOk =
            (Arc::new(election_parameters_info), produce_resource);
        return Some(Ok(production_result_ok));
    }

    // Obtain a validated FixedParameters from the cache, or try to produce a ConcreteType FixedParamsInfo.
    let fixed_parameters = {
        let mut ridfmt = ResourceIdFormat {
            rid: ResourceId::ElectionDataObject(EdoId::FixedParameters),
            fmt: ResourceFormat::ValidElectionDataObject,
        };
        let opt_result = rp_op
            .resources()
            .obtain_resource_production_result_from_cache_downcast_no_src::<FixedParameters>(
                &ridfmt,
            )
            .await;
        if let Some(Ok(arc_fixed_parameters)) = opt_result {
            debug!("Obtained {ridfmt} from cache");
            Either::Right(arc_fixed_parameters)
        } else {
            ridfmt.fmt = ResourceFormat::ConcreteType;
            match rp_op
                .produce_resource_downcast_no_src::<FixedParametersInfo>(&ridfmt)
                .await
            {
                Ok(arc_fixed_parameters_info) => Either::Left(arc_fixed_parameters_info),
                Err(e) => return Some(Err(e)),
            }
        }
    };

    // Obtain a validated VaryingParameters from the cache, or try to produce a ConcreteType VaryingParamsInfo.
    let varying_parameters = {
        let mut ridfmt = ResourceIdFormat {
            rid: ResourceId::ElectionDataObject(EdoId::VaryingParameters),
            fmt: ResourceFormat::ValidElectionDataObject,
        };
        let opt_result = rp_op
            .resources()
            .obtain_resource_production_result_from_cache_downcast_no_src::<VaryingParameters>(
                &ridfmt,
            )
            .await;
        if let Some(Ok(arc_varying_parameters)) = opt_result {
            debug!("Obtained {ridfmt} from cache");
            Either::Right(arc_varying_parameters)
        } else {
            ridfmt.fmt = ResourceFormat::ConcreteType;
            match rp_op
                .produce_resource_downcast_no_src::<VaryingParametersInfo>(&ridfmt)
                .await
            {
                Ok(arc_varying_parameters_info) => Either::Left(arc_varying_parameters_info),
                Err(e) => return Some(Err(e)),
            }
        }
    };

    let election_parameters_info = ElectionParametersInfo {
        fixed_parameters,
        varying_parameters,
    };

    Some(Ok((
        Arc::new(election_parameters_info),
        ResourceSource::constructed_concretetype(),
    )))
}

//=================================================================================================|

fn gather_rpspecific_registrations(register_fn: &mut dyn FnMut(RPFnRegistration)) {
    register_fn(RPFnRegistration::new_defaultproducer(
        ResourceIdFormat {
            rid: RID_ElectionParameters,
            fmt: ResourceFormat::ConcreteType,
        },
        Box::new(maybe_produce_ElectionParameters_ConcreteType),
    ));
}

inventory::submit! {
    GatherRPFnRegistrationsFnWrapper(gather_rpspecific_registrations)
}

//=================================================================================================|

//? TODO impl test
