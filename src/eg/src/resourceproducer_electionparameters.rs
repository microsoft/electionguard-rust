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
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::{borrow::Cow, rc::Rc};

use serde::Serialize;
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

use crate::{
    eg::{Eg, RsrcCacheMap},
    loadable::KnowsFriendlyTypeName,
    resource::{
        ElectionDataObjectId as EdoId, Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionResult,
        ResourceSource,
    },
    resource_producer_registry::{
        FnNewResourceProducer, GatherResourceProducerRegistrationsFnWrapper,
        ResourceProducerCategory, ResourceProducerRegistration, ResourceProducerRegistry,
    },
    resource_production::RpOp,
    validatable::Validated,
};

//=================================================================================================|

/// A [`ResourceProducer`] that attempts to assemble an [`ElectionParametersInfo`].
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct ResourceProducer_ElectionParametersInfo;

impl ResourceProducer_ElectionParametersInfo {
    fn rc_new() -> Rc<dyn ResourceProducer_Any_Debug_Serialize> {
        let self_ = Self;
        Rc::new(self_)
    }
}

impl ResourceProducer for ResourceProducer_ElectionParametersInfo {
    fn name(&self) -> Cow<'static, str> {
        "ElectionParametersInfo".into()
    }

    fn fn_rc_new(&self) -> FnNewResourceProducer {
        Self::rc_new
    }

    #[instrument(
        name = "ResourceProducer_ElectionParametersInfo::maybe_produce",
        fields(rf = trace_display(&rp_op.target_ridfmt)),
        skip(self, eg, rp_op),
        ret
    )]
    fn maybe_produce(&self, eg: &Eg, rp_op: &mut RpOp) -> Option<ResourceProductionResult> {
        use EdoId::*;
        use ResourceFormat::{ConcreteType, ValidatedElectionDataObject};
        //? use ResourceId::ElectionDataObject;
        //? let ridfmt_orig_request = ridfmt.clone();//?
        //? // We only handle the case of requesting a validated ElectionDataObject.
        //? // (Also, this extracts `edoid`.)
        //? let ResourceIdFormat {
        //?     rid: ElectionDataObject(edoid),
        //?     fmt: ValidatedElectionDataObject,
        //? } = ridfmt
        //? else {
        //?     return None;
        //? };//?
        //? // Try to obtain the resource in its not-yet-validated `Info` format.//?
        //? let ridfmt_info_concrete = ResourceIdFormat {
        //?     rid: ridfmt.rid.clone(),
        //?     fmt: ConcreteType,
        //? };//?
        //? let dependency_production_result = eg.produce_resource(&ridfmt_info_concrete);//?
        //? match dependency_production_result {
        //?     Err(ResourceProductionError::NoProducerConfigured { .. }) => {
        //?         None
        //?     }
        //?     Err(dep_err) => {
        //?         let e = ResourceProductionError::DependencyProductionError {
        //?             ridfmt_request: ridfmt.clone(),
        //?             dep_err: Box::new(dep_err),
        //?         };
        //?         error!("{e:?}");
        //?         Some(Err(e))
        //?     }
        //?     Ok((rc_dyn_resource, rsrc_concrete)) => {
        //?         // We managed to produce the resource.
        //?         // Continue on to the next function to try to validate it to the type we need.
        //?         debug_assert_eq!(rc_dyn_resource.ridfmt(), &ridfmt_info_concrete);
        //?         self.maybe_produce2_(
        //?             eg,
        //?             edoid,
        //?             &ridfmt_orig_request,
        //?             rc_dyn_resource,
        //?             rsrc_concrete )
        //?     }
        //? }
        None
    }
}

//=================================================================================================|

fn gather_resourceproducer_registrations_ElectionParametersInfo(
    f: &mut dyn FnMut(&[ResourceProducerRegistration]),
) {
    f(&[ResourceProducerRegistration::new_defaultproducer(
        "ElectionParametersInfo",
        ResourceProducer_ElectionParametersInfo::rc_new,
    )]);
}

inventory::submit! {
    GatherResourceProducerRegistrationsFnWrapper(gather_resourceproducer_registrations_ElectionParametersInfo)
}

//=================================================================================================|

//? #[cfg(test)]
//? #[allow(clippy::unwrap_used)]
//? mod t {
//?     use super::*;
//?     use anyhow::{anyhow, bail, ensure, Context, Result};
//?     use insta::assert_ron_snapshot;
//?
//?     use crate::eg_config::EgConfig;
//?     use crate::resource::ElectionDataObjectId as EdoId;
//?
//?     #[test]
//?     fn t0() {
//?         let eg = &Eg::new_insecure_deterministic_with_example_election_data(
//?             "eg::resource_provider_validatetoedo::t::t0",
//?         )
//?         .unwrap();
//?
//?         {
//?             let (dr_rc, dr_src) = eg
//?                 .produce_resource(&ResourceIdFormat {
//?                     rid: ResourceId::ElectionDataObject(EdoId::ElectionManifest),
//?                     fmt: ResourceFormat::SliceBytes,
//?                 })
//?                 .unwrap();
//?             assert_ron_snapshot!(dr_rc.rid(), @"ElectionDataObject(ElectionManifest)");
//?             assert_ron_snapshot!(dr_rc.format(), @r#"SliceBytes"#);
//?             assert_ron_snapshot!(dr_src, @"ExampleData(SliceBytes)");
//?             assert_ron_snapshot!(dr_rc.as_slice_bytes().is_some(), @r#"true"#);
//?             assert_ron_snapshot!(10 < dr_rc.as_slice_bytes().unwrap().len(), @r#"true"#);
//?             //assert_ron_snapshot!(dr_rc.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()), @r#"Some("{...}")"#);
//?         }
//?
//?         {
//?             let result = eg.produce_resource(&ResourceIdFormat {
//?                 rid: ResourceId::ElectionDataObject(EdoId::ElectionManifest),
//?                 fmt: ResourceFormat::ConcreteType,
//?             });
//?             assert_ron_snapshot!(result, @r#"
//?             Err(NoProducerConfigured(
//?               ridfmt: ResourceIdFormat(
//?                 id: ElectionDataObject(ElectionManifest),
//?                 fmt: ConcreteType,
//?               ),
//?             ))
//?             "#);
//?         }
//?
//?         /*
//?         {
//?             let (dr_rc, dr_src) = eg
//?                 .produce_resource(&ResourceIdFormat {
//?                     id: ResourceId::ElectionDataObject(EdoId::ElectionManifest),
//?                     fmt: ResourceFormat::ValidatedElectionDataObject,
//?                 })
//?                 .unwrap();
//?             assert_ron_snapshot!(dr_rc.rid(), @r#"PersistedElectionDataObject(ElectionManifest)"#);
//?             assert_ron_snapshot!(dr_rc.format(), @"ValidatedElectionDataObject");
//?             assert_ron_snapshot!(dr_src, @"ExampleData");
//?         }
//?         // */
//?     }
//? }
