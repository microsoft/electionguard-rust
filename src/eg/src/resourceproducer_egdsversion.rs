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

use std::{borrow::Cow, sync::Arc};

use serde::Serialize;
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

use crate::{
    eg::Eg,
    resource::{
        ProduceResource, ProduceResourceExt, Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionError,
        ResourceProductionResult, ResourceSource,
    },
    resource_producer_registry::{
        FnNewResourceProducer, GatherResourceProducerRegistrationsFnWrapper, RPFnRegistration,
        ResourceProducerCategory, ResourceProducerRegistration, ResourceProducerRegistry,
    },
    resource_production::RpOp,
    resource_slicebytes::ResourceSliceBytes,
    resourceproducer_specific::GatherRPFnRegistrationsFnWrapper,
};

//=================================================================================================|

#[allow(non_snake_case)]
fn maybe_produce_ElectionGuardDesignSpecificationVersion_ConcreteType(
    rp_op: &Arc<RpOp>,
) -> Option<ResourceProductionResult> {
    let ridfmt_expected = ResourceIdFormat {
        rid: ResourceId::ElectionGuardDesignSpecificationVersion,
        fmt: ResourceFormat::ConcreteType,
    };

    let ridfmt_requested = rp_op.requested_ridfmt();

    if rp_op.requested_ridfmt().as_ref() != &ridfmt_expected {
        return Some(Err(
            ResourceProductionError::UnexpectedResourceIdFormatRequested {
                ridfmt_expected,
                ridfmt_requested: ridfmt_requested.into_owned(),
            },
        ));
    }

    let arc: Arc<dyn Resource> = Arc::new(crate::EGDS_VERSION.clone());
    let rpsrc = ResourceSource::constructed_concretetype();
    let result: ResourceProductionResult = Ok((arc, rpsrc));
    Some(result)
}

//=================================================================================================|

fn gather_rpspecific_registrations(register_fn: &mut dyn FnMut(RPFnRegistration)) {
    /* //? TODO remove, this should now be handled by resourceproducer_SerializeFromValidated
    register_fn(RPFnRegistration::new_defaultproducer(
        ResourceIdFormat {
            rid: ResourceId::ElectionGuardDesignSpecificationVersion,
            fmt: ResourceFormat::SliceBytes,
        },
        Box::new(maybe_produce_ElectionGuardDesignSpecificationVersion_SliceBytes),
    ));
    // */

    register_fn(RPFnRegistration::new_defaultproducer(
        ResourceIdFormat {
            rid: ResourceId::ElectionGuardDesignSpecificationVersion,
            fmt: ResourceFormat::ConcreteType,
        },
        Box::new(maybe_produce_ElectionGuardDesignSpecificationVersion_ConcreteType),
    ));
}

inventory::submit! {
    GatherRPFnRegistrationsFnWrapper(gather_rpspecific_registrations)
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use insta::{assert_json_snapshot, assert_ron_snapshot};

    use super::*;
    use crate::egds_version::ElectionGuard_DesignSpecification_Version;

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_insecure_deterministic_csprng_seed(
                "eg::resourceproducer_egdsversion::t::t1",
            );
            let eg = eg.as_ref();

            let (arc_egdsv, resource_source) = eg
                .produce_resource_downcast::<ElectionGuard_DesignSpecification_Version>(
                    &ResourceIdFormat {
                        rid: ResourceId::ElectionGuardDesignSpecificationVersion,
                        fmt: ResourceFormat::ConcreteType,
                    },
                )
                .await
                .unwrap();

            assert_ron_snapshot!(arc_egdsv.rid(), @r#"ElectionGuardDesignSpecificationVersion"#);
            assert_ron_snapshot!(arc_egdsv.format(), @"ConcreteType");
            assert_ron_snapshot!(resource_source, @"Constructed(ConcreteType)");
            assert_ron_snapshot!(arc_egdsv.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()),
            @r#"None"#);

            assert_json_snapshot!(arc_egdsv, @r#"
            {
              "version_number": [
                2,
                1
              ],
              "qualifier": "Released_Specification_Version",
              "fixed_parameters_kind": "Standard_Parameters"
            }
            "#);
        });
    }
}
