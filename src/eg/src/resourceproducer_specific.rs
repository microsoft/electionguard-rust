// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
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
#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    //path::{Path, PathBuf},
    sync::Arc,
    //str::FromStr,
    //sync::OnceLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
use static_assertions::{assert_cfg, assert_impl_all, assert_obj_safe, const_assert};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};

use crate::{
    eg::Eg,
    loadable::KnowsFriendlyTypeName,
    resource::{
        ElectionDataObjectId as EdoId, ProduceResource, ProduceResourceExt, Resource,
        ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionResult,
        ResourceSource,
    },
    resource_producer_registry::{
        FnNewResourceProducer, GatherResourceProducerRegistrationsFnWrapper, RPFnRegistration,
        ResourceProducerCategory, ResourceProducerRegistration, ResourceProducerRegistry,
    },
    resource_production::RpOp,
    validatable::Validated,
};

//=================================================================================================|

/// A [`ResourceProducer`] that attempts to assemble a resource from a pre-registered function.
#[allow(non_camel_case_types)]
#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct ResourceProducer_Specific {
    #[serde(skip)]
    v: Vec<RPFnRegistration>,
}

impl ResourceProducer_Specific {
    fn arc_new() -> Arc<dyn ResourceProducer_Any_Debug_Serialize> {
        let self_ = Self::new();
        Arc::new(self_)
    }

    fn new() -> Self {
        type FnMut_<'a> = &'a mut dyn FnMut(RPFnRegistration);

        let mut v = vec![];

        let f: FnMut_ = &mut |rpspecific_registration| {
            v.push(rpspecific_registration);
        };

        for rpspecific_registration_fn_wrapper in
            inventory::iter::<GatherRPFnRegistrationsFnWrapper>
        {
            let rpspecific_registration_fn = rpspecific_registration_fn_wrapper.0;
            rpspecific_registration_fn(f);
        }

        //? TODO sort v by cost

        Self { v }
    }
}

impl ResourceProducer for ResourceProducer_Specific {
    fn name(&self) -> Cow<'static, str> {
        "Specific".into()
    }

    fn fn_rc_new(&self) -> FnNewResourceProducer {
        Self::arc_new
    }

    /*
    #[instrument(
        name = "ResourceProducer_Specific::maybe_produce",
        fields(rf = trace_display(&rp_op.target_ridfmt)),
        skip(self, eg, rp_op),
        ret
    )]
    // */
    fn maybe_produce(&self, rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
        for rpspecific_registration in &self.v {
            if rpspecific_registration.ridfmt() == rp_op.requested_ridfmt() {
                let fn_maybe_produce = rpspecific_registration.fn_maybe_produce.as_ref();
                let opt_rp_result = fn_maybe_produce(rp_op);
                if opt_rp_result.is_some() {
                    //?? TODO double check resulting ridfmt? Or does the caller do that?
                    return opt_rp_result;
                }
            }
        }

        None
    }
}

assert_impl_all!(ResourceProducer_Specific: Send, Sync, Unpin);

//-------------------------------------------------------------------------------------------------|

pub type GatherRPFnRegistrationsFn = fn(&mut dyn FnMut(RPFnRegistration));

/// Wrapper type to identify the collection of [`RegisterResourceProducerFactoryFn`]s for
/// [`inventory`].
pub struct GatherRPFnRegistrationsFnWrapper(pub GatherRPFnRegistrationsFn);

inventory::collect!(GatherRPFnRegistrationsFnWrapper);

//=================================================================================================|

fn gather_resourceproducer_registrations_Specific(
    f: &mut dyn for<'a> FnMut(&'a [ResourceProducerRegistration]),
) {
    f(&[ResourceProducerRegistration::new_defaultproducer(
        "Specific",
        ResourceProducer_Specific::arc_new,
    )]);
}

inventory::submit! {
    GatherResourceProducerRegistrationsFnWrapper(gather_resourceproducer_registrations_Specific)
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use insta::assert_ron_snapshot;

    use super::*;

    #[test]
    fn t1() {
        async_global_executor::block_on(t1_async());
    }

    async fn t1_async() {
        let eg =
            Eg::new_with_insecure_deterministic_csprng_seed("eg::resourceproducer_specific::t::t0");
        let eg = eg.as_ref();

        let (dr_rc, dr_src) = eg
            .produce_resource(&ResourceIdFormat {
                rid: ResourceId::ElectionGuardDesignSpecificationVersion,
                fmt: ResourceFormat::ConcreteType,
            })
            .await
            .unwrap();

        assert_ron_snapshot!(dr_rc.rid(), @"ElectionGuardDesignSpecificationVersion");
        assert_ron_snapshot!(dr_rc.format(), @"ConcreteType");
        assert_ron_snapshot!(dr_src, @"Constructed(ConcreteType)");
        assert_ron_snapshot!(dr_rc.as_slice_bytes().map(|aby|std::str::from_utf8(aby).unwrap()),
            @r#"None"#);
    }
}
