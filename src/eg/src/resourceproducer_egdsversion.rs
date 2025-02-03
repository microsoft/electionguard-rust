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

use std::{borrow::Cow, rc::Rc};

use serde::Serialize;
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

use crate::{
    eg::Eg,
    resource::{Resource, ResourceFormat, ResourceId, ResourceIdFormat},
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

/*
/// A built-in [`ResourceProducer`] that provides [`ResourceId::ElectionGuardDesignSpecificationVersion`].
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct ResourceProducer_ElectionGuardDesignSpecificationVersion;

impl ResourceProducer_ElectionGuardDesignSpecificationVersion {
    fn rc_new() -> Rc<dyn ResourceProducer_Any_Debug_Serialize> {
        let self_ = Self;
        Rc::new(self_)
    }
}

impl ResourceProducer for ResourceProducer_ElectionGuardDesignSpecificationVersion {
    fn name(&self) -> Cow<'static, str> {
        "ElectionGuardDesignSpecificationVersion".into()
    }

    fn fn_rc_new(&self) -> FnNewResourceProducer {
        Self::rc_new
    }

    #[instrument(
        name = "ResourceProducer_ElectionGuardDesignSpecificationVersion::maybe_produce",
        fields(rf = trace_display(&rp_op.target_ridfmt)),
        skip(self, _eg, rp_op),
        ret
    )]
    fn maybe_produce(
        &self,
        _eg: &Eg,
        rp_op: &mut RpOp,
    ) -> Option<ResourceProductionResult> {
        use ResourceFormat::{ConcreteType, SliceBytes};
        use ResourceId::ElectionGuardDesignSpecificationVersion;
        match rp_op.target_ridfmt {
            ResourceIdFormat {
                rid: ElectionGuardDesignSpecificationVersion,
                fmt: SliceBytes,
            } => {
                // Unwrap() is justified here because this is a fixed structure that should
                // predictably convert to json.
                #[allow(clippy::unwrap_used)]
                let vby = serde_json::to_vec(&crate::EGDS_VERSION).unwrap();
                let drsb = ResourceSliceBytes::new(&rp_op.target_ridfmt.rid, vby);
                let rc: Rc<dyn Resource> = Rc::new(drsb);
                let rpsrc = ResourceSource::slicebytes_serializedfrom_constructed_concretetype();
                let result: ResourceProductionResult = Ok((rc, rpsrc));
                Some(result)
            }
            ResourceIdFormat {
                rid: ElectionGuardDesignSpecificationVersion,
                fmt: ConcreteType,
            } => {
                let rc: Rc<dyn Resource> = Rc::new(crate::EGDS_VERSION);
                let rpsrc = ResourceSource::constructed_concretetype();
                let result: ResourceProductionResult = Ok((rc, rpsrc));
                Some(result)
            }
            _ => None,
        }
        None
    }
}

fn gather_resourceproducer_registrations_ElectionGuardDesignSpecificationVersion(
    f: &mut dyn FnMut(&[ResourceProducerRegistration]),
) {
    f(&[ResourceProducerRegistration::new_defaultproducer(
        "ElectionGuardDesignSpecificationVersion",
        ResourceProducer_ElectionGuardDesignSpecificationVersion::rc_new,
    )]);
}

inventory::submit! {
    GatherResourceProducerRegistrationsFnWrapper(gather_resourceproducer_registrations_ElectionGuardDesignSpecificationVersion)
}
// */

//=================================================================================================|

#[allow(non_snake_case)]
fn maybe_produce_ElectionGuardDesignSpecificationVersion_SliceBytes(
    _eg: &Eg,
    rp_op: &mut RpOp,
) -> Option<ResourceProductionResult> {
    let ridfmt_expected = ResourceIdFormat {
        rid: ResourceId::ElectionGuardDesignSpecificationVersion,
        fmt: ResourceFormat::SliceBytes,
    };

    let ridfmt_requested = rp_op.target_ridfmt();

    if rp_op.target_ridfmt() != &ridfmt_expected {
        return Some(Err(
            ResourceProductionError::UnexpectedResourceIdFormatRequested {
                ridfmt_expected,
                ridfmt_requested: ridfmt_requested.clone(),
            },
        ));
    }

    // Unwrap() is justified here because this is a fixed structure that should
    // predictably convert to json.
    #[allow(clippy::unwrap_used)]
    let vby = serde_json::to_vec(&crate::EGDS_VERSION).unwrap();
    let drsb = ResourceSliceBytes::new(&rp_op.target_ridfmt.rid, vby);
    let rc: Rc<dyn Resource> = Rc::new(drsb);
    let rpsrc = ResourceSource::slicebytes_serializedfrom_constructed_concretetype();
    let result: ResourceProductionResult = Ok((rc, rpsrc));
    Some(result)
}

//=================================================================================================|

#[allow(non_snake_case)]
fn maybe_produce_ElectionGuardDesignSpecificationVersion_ConcreteType(
    _eg: &Eg,
    rp_op: &mut RpOp,
) -> Option<ResourceProductionResult> {
    let ridfmt_expected = ResourceIdFormat {
        rid: ResourceId::ElectionGuardDesignSpecificationVersion,
        fmt: ResourceFormat::ConcreteType,
    };

    let ridfmt_requested = rp_op.target_ridfmt();

    if rp_op.target_ridfmt() != &ridfmt_expected {
        return Some(Err(
            ResourceProductionError::UnexpectedResourceIdFormatRequested {
                ridfmt_expected,
                ridfmt_requested: ridfmt_requested.clone(),
            },
        ));
    }

    let rc: Rc<dyn Resource> = Rc::new(crate::EGDS_VERSION);
    let rpsrc = ResourceSource::constructed_concretetype();
    let result: ResourceProductionResult = Ok((rc, rpsrc));
    Some(result)
}

//=================================================================================================|

fn gather_rpspecific_registrations(register_fn: &mut dyn FnMut(RPFnRegistration)) {
    register_fn(RPFnRegistration::new_defaultproducer(
        ResourceIdFormat {
            rid: ResourceId::ElectionGuardDesignSpecificationVersion,
            fmt: ResourceFormat::SliceBytes,
        },
        Box::new(maybe_produce_ElectionGuardDesignSpecificationVersion_SliceBytes),
    ));

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
    use insta::assert_ron_snapshot;

    use super::*;

    #[test]
    fn t0() {
        let eg = &Eg::new_with_insecure_deterministic_csprng_seed(
            "eg::resourceproducer_egdsversion::t::t0",
        );

        // Trivial success cases.

        let (dr_rc, dr_src) = eg
            .produce_resource(&ResourceIdFormat {
                rid: ResourceId::ElectionGuardDesignSpecificationVersion,
                fmt: ResourceFormat::SliceBytes,
            })
            .unwrap();

        assert_ron_snapshot!(dr_rc.rid(), @r#"ElectionGuardDesignSpecificationVersion"#);
        assert_ron_snapshot!(dr_rc.format(), @r#"SliceBytes"#);
        assert_ron_snapshot!(dr_src, @"SerializedFrom(SliceBytes, Constructed(ConcreteType))");
        assert_ron_snapshot!(dr_rc.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()),
            @r#"Some("{\"number\":[2,1]}")"#);
    }

    #[test]
    fn t1() {
        let eg = &Eg::new_with_insecure_deterministic_csprng_seed(
            "eg::resourceproducer_egdsversion::t::t1",
        );

        let (dr_rc, dr_src) = eg
            .produce_resource(&ResourceIdFormat {
                rid: ResourceId::ElectionGuardDesignSpecificationVersion,
                fmt: ResourceFormat::ConcreteType,
            })
            .unwrap();

        assert_ron_snapshot!(dr_rc.rid(), @r#"ElectionGuardDesignSpecificationVersion"#);
        assert_ron_snapshot!(dr_rc.format(), @"ConcreteType");
        assert_ron_snapshot!(dr_src, @"Constructed(ConcreteType)");
        assert_ron_snapshot!(dr_rc.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()),
            @r#"None"#);
    }
}
