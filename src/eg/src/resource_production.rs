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
    //borrow::Cow,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    //path::{Path, PathBuf},
    rc::Rc,
    //str::FromStr,
    //sync::OnceLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
use itertools::Itertools;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn, Span,
};
use util::abbreviation::Abbreviation;

use crate::{
    eg::{Eg, RsrcCacheMap},
    errors::{EgError, EgResult},
    guardian_secret_key::GuardianIndex,
    resource::{ElectionDataObjectId, Resource, ResourceFormat, ResourceId, ResourceIdFormat},
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionError,
        ResourceProductionOk, ResourceProductionResult,
    },
};

//=================================================================================================|

/// Context for a particular ResourceProduction operation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct RpOp<'a> {
    pub target_ridfmt: ResourceIdFormat,

    #[serde(serialize_with = "util::serde::serialize_opt_opaque_as_str")]
    pub opt_span: Option<&'a Span>,

    pub opt_outer_op: Option<&'a RpOp<'a>>,
}

impl<'a> RpOp<'a> {
    /// Makes a new ResourceProductionOperation
    pub(crate) fn new(
        target_ridfmt: ResourceIdFormat,
        span: &'a Span,
        opt_outer_op: Option<&'a RpOp<'a>>,
    ) -> Self {
        let opt_span = if span.is_disabled() { None } else { Some(span) };
        Self {
            target_ridfmt,
            opt_span,
            opt_outer_op,
        }
    }

    pub fn target_ridfmt(&self) -> &ResourceIdFormat {
        &self.target_ridfmt
    }

    pub fn target_rid(&self) -> &ResourceId {
        &self.target_ridfmt.rid
    }

    pub fn target_fmt(&self) -> &ResourceFormat {
        &self.target_ridfmt.fmt
    }

    pub fn opt_outer_op(&self) -> &Option<&'a RpOp<'a>> {
        &self.opt_outer_op
    }

    /// Call this to produce a resource from within an active [`RpOp`].
    pub fn produce_resource(
        &mut self,
        eg: &Eg,
        target_ridfmt: ResourceIdFormat,
    ) -> ResourceProductionResult {
        let span = trace_span!(
            "inner_produce",
            rf = tracing::field::display(target_ridfmt.abbreviation())
        );

        let _enter_span = span.enter();

        let mut rp_op2 = RpOp::new(target_ridfmt, &span, Some(self));

        produce_resource_impl_(eg, &mut rp_op2)
    }
}

//=================================================================================================|

pub(crate) fn produce_resource_impl_(eg: &Eg, rp_op: &mut RpOp) -> ResourceProductionResult {
    // If we already have this resource cached, simply return a result based on that.
    if let Some(rprod_result) =
        produce_resource_result_from_cache(eg.resource_cache_try_borrow()?, rp_op)
    {
        return rprod_result;
    }

    // Detect recursion and return an error result.
    produce_resource_detect_recursion(rp_op)?;

    // Try to produce the resource from the producers.

    let opt_rprod_result = produce_resource_from_producers(eg, rp_op);

    if let Some(rprod_result) = opt_rprod_result {
        // The providers yielded a result.
        if let Ok(rprod_result_ok) = &rprod_result {
            // We were able to produce the resource from some sequence of providers.
            // Save it to the cache.
            produce_resource_result_ok_save_to_cache(
                eg.resource_cache_try_borrow_mut()?,
                rprod_result_ok,
            )?;
        }
        rprod_result
    } else {
        // The providers did not yield any result.
        Err(ResourceProductionError::NoProducerFound {
            ridfmt: rp_op.target_ridfmt().clone(),
        })
    }
}

fn produce_resource_result_from_cache(
    resource_cache: std::cell::Ref<'_, RsrcCacheMap>,
    rp_op: &mut RpOp,
) -> Option<ResourceProductionResult> {
    #[allow(clippy::manual_map)]
    match resource_cache.get(rp_op.target_ridfmt()) {
        None => {
            // Requested data resource was not found in cache.
            None
        }
        Some(val) => {
            // The requested data resource was found in cache, return it.
            Some(Ok(val.clone()))
        }
    }
}

fn produce_resource_detect_recursion(rp_op: &RpOp) -> Result<(), ResourceProductionError> {
    let mut opt_recursion_detected_level = None;
    {
        let mut level = 0_usize;
        let mut op = rp_op;
        loop {
            if 0 < level && op.target_ridfmt() == rp_op.target_ridfmt() {
                opt_recursion_detected_level = Some(level);
            }

            if let Some(outer_op) = op.opt_outer_op() {
                level += 1;
                op = outer_op;
            } else {
                break;
            }
        }
    }

    let Some(recursion_level) = opt_recursion_detected_level else {
        return Ok(());
    };

    let v_strings = {
        let mut v = vec![];
        let mut level = 0_usize;
        let mut op = rp_op;
        loop {
            let mut s = op.target_ridfmt().abbreviation().into_owned();
            if level == 0 {
                s = format!("{{ recurs here: {s} }}");
            } else if level == recursion_level {
                s = format!("{{ this request: {s} }}");
            }
            v.push(s);

            if let Some(outer_op) = op.opt_outer_op() {
                level += 1;
                op = outer_op;
            } else {
                break;
            }
        }
        v.reverse();
        v
    };

    let chain = v_strings.into_iter().join(" -> ");
    warn!("Recursion detected during resource production: {chain}");

    Err(ResourceProductionError::RecursionDetected {
        ridfmt_request: rp_op.target_ridfmt().clone(),
        chain,
    })
}

fn produce_resource_from_producers(eg: &Eg, rp_op: &mut RpOp) -> Option<ResourceProductionResult> {
    // Try each registered ResourceProducer in order, returning the first result.
    //? TODO iterate in priority order?

    //debug!("Iterating registrations vvvvvvvvvvvvvvvvvvvvvvvvvvvv");
    for registryentry in eg.config().resourceproducer_registry().registrations() {
        debug!("Provider registry entry: {registryentry:?}");

        let rc_resource_producer = registryentry.get_or_create_resourceproducer();

        debug!("-- obtained {rc_resource_producer:?}");

        let opt_result = rc_resource_producer.maybe_produce(eg, rp_op);

        if opt_result.is_some() {
            opt_result.as_ref().inspect(|&result| {
                debug!("resource_producer.maybe_produce() -> `Some`: {result:?}");
            });

            // This provider has yielded a result, return it.
            return opt_result;
        }
    }
    //debug!("Iterating registrations ^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

    None
}

fn produce_resource_result_ok_save_to_cache(
    mut rsrc_cache: std::cell::RefMut<'_, RsrcCacheMap>,
    rprod_ok: &ResourceProductionOk,
) -> Result<(), ResourceProductionError> {
    use std::collections::btree_map::{Entry::*, OccupiedEntry, VacantEntry};

    let (rc_dr_produced, dr_production_source) = rprod_ok;
    let ridfmt_produced = rc_dr_produced.ridfmt().clone();

    match rsrc_cache.entry(ridfmt_produced.clone()) {
        Vacant(vacant_entry) => {
            vacant_entry.insert((rc_dr_produced.clone(), dr_production_source.clone()));
            Ok(())
        }
        Occupied(occupied_entry) => {
            let rc_occupied_entry = &occupied_entry.get().0;
            debug_assert_eq!(&ridfmt_produced, rc_occupied_entry.ridfmt());

            if Rc::ptr_eq(rc_dr_produced, rc_occupied_entry) {
                // Somehow, between the time this production request was started and now,
                // this data resource (instance) got cached already.
                // Surprising, but not an error.
                info!(
                    rf = trace_display(ridfmt_produced),
                    "Resource already present in cache"
                );

                Ok(())
            } else {
                // Somehow, between the time this production request was started and now,
                // a different data resource (instance) got cached for this same ridfmt.
                let source_of_existing = occupied_entry.get().1.clone();
                let e = ResourceProductionError::ResourceAlreadyStored {
                    ridfmt: ridfmt_produced.clone(),
                    source_of_existing: source_of_existing.clone(),
                };
                error!(
                    produced = trace_display(ridfmt_produced),
                    source_of_existing = trace_display(source_of_existing),
                    "Resource already present in cache: {e}"
                );

                Err(e)
            }
        }
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{anyhow, bail, ensure, Context, Result};
    use insta::assert_ron_snapshot;

    use super::*;
    use crate::eg_config::EgConfig;
    use crate::resource::ElectionDataObjectId;

    #[test]
    fn t0() {
        let eg = &Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::resource_production::t::t2",
        );

        // Failure cases where we don't have a ResourceProducer set up to handle the request.

        let rid_edo_pvd = ResourceId::ElectionDataObject(ElectionDataObjectId::PreVotingData);
        assert_ron_snapshot!(eg.produce_resource(
            &ResourceIdFormat {
                rid: rid_edo_pvd.clone(),
                fmt: ResourceFormat::SliceBytes,
            }
        ).err(), @r#"
        Some(NoProducerFound(
          ridfmt: ResourceIdFormat(
            rid: ElectionDataObject(PreVotingData),
            fmt: SliceBytes,
          ),
        ))
        "#);

        assert_ron_snapshot!(eg.produce_resource(
            &ResourceIdFormat {
                rid: rid_edo_pvd.clone(),
                fmt: ResourceFormat::ConcreteType,
            }
        ).err(), @r#"
        Some(NoProducerFound(
          ridfmt: ResourceIdFormat(
            rid: ElectionDataObject(PreVotingData),
            fmt: ConcreteType,
          ),
        ))
        "#);
    }
}
