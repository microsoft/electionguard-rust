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
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    //path::{Path, PathBuf},
    any::Any,
    borrow::Cow,
    pin::Pin,
    sync::{Arc, Weak},
};

use futures_lite::FutureExt;
//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
use itertools::Itertools;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tracing::{
    Instrument, Span, debug, debug_span, error, field::display as trace_display, info, info_span,
    instrument, trace, trace_span, warn,
};
use util::abbreviation::Abbreviation;

use crate::{
    eg::Eg,
    errors::{EgError, EgResult},
    guardian_secret_key::GuardianIndex,
    resource::{
        ElectionDataObjectId, ProduceResource, ProduceResourceExt, ProductionBudget, Resource,
        ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionError,
        ResourceProductionOk, ResourceProductionResult, ResourceSource,
    },
    resources::Resources,
};

//=================================================================================================|

/// Context for a particular ResourceProduction operation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct RpOp {
    weak_self: Weak<Self>,

    eg: Arc<Eg>,

    resources: Arc<Resources>,

    ridfmt: ResourceIdFormat,

    #[serde(skip)]
    trace_field_rf: tracing::field::DisplayValue<Cow<'static, str>>,

    prod_budget: ProductionBudget,

    #[serde(serialize_with = "util::serde::serialize_opt_opaque_as_str")]
    opt_span: Option<Span>,

    opt_outer_op: Option<Weak<RpOp>>,
}

impl RpOp {
    /// Makes a new ResourceProductionOperation
    pub(crate) fn new(
        eg: Arc<Eg>,
        resources: Arc<Resources>,
        ridfmt: ResourceIdFormat,
        opt_prod_budget: Option<ProductionBudget>,
        opt_span: Option<Span>,
        opt_outer_op: Option<Arc<RpOp>>,
    ) -> Arc<Self> {
        let trace_field_rf = trace_display(ridfmt.abbreviation());

        let mut opt_span = opt_span.filter(|sp| !sp.is_disabled());

        if let Some(span) = &mut opt_span {
            span.record("rf", trace_field_rf.clone());
        }

        // The ProductionBudget is the smaller of any provided arg and any outer_op budget.
        // If neither, default is Unlimited.
        let prod_budget = {
            let pb_supplied = opt_prod_budget.unwrap_or(ProductionBudget::Unlimited);
            let pb_outer = opt_outer_op
                .as_ref()
                .map(|outer_op| outer_op.prod_budget())
                .copied()
                .unwrap_or(ProductionBudget::Unlimited);
            pb_supplied.min(pb_outer)
        };

        let opt_outer_op = opt_outer_op.map(|outer_op| Arc::downgrade(&outer_op));
        Arc::new_cyclic(|w| Self {
            weak_self: w.clone(),
            eg,
            resources,
            ridfmt,
            trace_field_rf,
            prod_budget,
            opt_span,
            opt_outer_op,
        })
    }

    /// Provides access to the [`RpOp`] as [`Weak<Self>`].
    #[inline]
    pub fn weak_self(&self) -> Weak<Self> {
        self.weak_self.clone()
    }

    /// Maybe provides access to the [`RpOp`] as [`Arc<Self>`].
    #[inline]
    pub fn opt_self(&self) -> Option<Arc<Self>> {
        self.weak_self.upgrade()
    }

    /// Provides access to the [`Eg`].
    #[inline]
    pub fn eg(&self) -> &Arc<Eg> {
        &self.eg
    }

    /// Provides access to the [`Resources`].
    #[inline]
    pub fn resources(&self) -> &Arc<Resources> {
        &self.resources
    }

    #[inline]
    pub fn requested_ridfmt(&self) -> Cow<'_, ResourceIdFormat> {
        Cow::Borrowed(&self.ridfmt)
    }

    #[inline]
    pub fn requested_rid(&self) -> Cow<'_, ResourceId> {
        Cow::Borrowed(&self.ridfmt.rid)
    }

    #[inline]
    pub fn requested_fmt(&self) -> Cow<'_, ResourceFormat> {
        Cow::Borrowed(&self.ridfmt.fmt)
    }

    #[inline]
    pub fn trace_field_rf(&self) -> &tracing::field::DisplayValue<Cow<'static, str>> {
        &self.trace_field_rf
    }

    #[inline]
    pub fn prod_budget(&self) -> &ProductionBudget {
        &self.prod_budget
    }

    pub fn opt_span(&self) -> Option<&Span> {
        self.opt_span.as_ref()
    }

    pub fn opt_outer_op(&self) -> Option<Arc<RpOp>> {
        self.opt_outer_op.as_ref().and_then(Weak::upgrade)
    }

    /// Helper function for producer functions to verify that
    /// the requested [`ResourceIdFormat`] is the one that they expect.
    pub fn check_ridfmt(
        &self,
        ridfmt_expected: &ResourceIdFormat,
    ) -> Result<(), ResourceProductionError> {
        if self.requested_ridfmt().as_ref() != ridfmt_expected {
            let e = ResourceProductionError::UnexpectedResourceIdFormatRequested {
                ridfmt_expected: ridfmt_expected.clone(),
                ridfmt_requested: self.requested_ridfmt().into_owned(),
            };
            Err(e)
        } else {
            Ok(())
        }
    }
}

impl ProduceResource for RpOp {
    fn csrng(&self) -> &dyn util::csrng::Csrng {
        self.eg.csrng()
    }

    fn trait_impl_produce_resource_<'a>(
        &'a self,
        ridfmt: ResourceIdFormat,
        opt_prod_budget: Option<ProductionBudget>,
    ) -> Pin<Box<dyn Future<Output = ResourceProductionResult> + Send + 'a>> {
        let ridfmt = ridfmt.clone();

        let span = debug_span!(
            "<RpOp as ProduceResource>::trait_impl_produce_resource_",
            rf = self.trace_field_rf(),
            rf_next = trace_display(ridfmt.abbreviation())
        )
        .or_current();

        let opt_self = self.opt_self();
        if opt_self.is_some() {
            let rp_op2 = RpOp::new(
                self.eg.clone(),
                self.resources.clone(),
                ridfmt,
                opt_prod_budget,
                Some(span),
                opt_self,
            );

            produce_resource_impl_(rp_op2)
        } else {
            let e = ResourceProductionError::ResourceNoLongerNeeded { ridfmt };
            error!("RpOp lost all incoming references: {e}");
            std::future::ready(Err(e)).boxed()
        }
    }
}

//=================================================================================================|

pub(crate) fn produce_resource_impl_<'a>(
    rp_op: Arc<RpOp>,
) -> Pin<Box<dyn Future<Output = ResourceProductionResult> + Send + 'a>> {
    let span = rp_op
        .opt_span()
        .filter(|&sp| !sp.is_disabled())
        .cloned()
        .unwrap_or_else(Span::current);

    async move {
        let ridfmt = rp_op.requested_ridfmt().into_owned();

        // If we already have this resource result cached, simply return that.
        let opt_result = rp_op
            .resources()
            .obtain_resource_production_result_from_cache(&ridfmt)
            .await;

        let production_budget = *rp_op.prod_budget();

        if production_budget.check_cache_only() {
            // A production_budget of zero indicates we should just check the cache test,
            // so the absence of the requested resource in the cache is not really an error.
            let e = ResourceProductionError::ProductionBudgetInsufficient {
                requested: ridfmt,
                production_budget,
            };
            trace!(rf = rp_op.trace_field_rf(), "Resource production: {e}");
            Err(e)
        } else if let Some(resource_production_result) = opt_result {
            resource_production_result
        } else {
            // Detect recursion and return an error result.
            produce_resource_detect_recursion(&rp_op)?;

            // Try to produce the resource from the producers.

            let opt_rprod_result = produce_resource_from_producers(&rp_op).await;

            if let Some(resource_production_result) = opt_rprod_result {
                // The providers yielded a result, record it, return it.
                rp_op
                    .resources()
                    .record_rprod_result(&ridfmt, resource_production_result.clone())
                    .await?;
                resource_production_result
            } else {
                // The providers did not yield any result.
                let e = ResourceProductionError::NoProducerFound {
                    ridfmt: rp_op.requested_ridfmt().into_owned(),
                };
                debug!(rf = rp_op.trace_field_rf(), "Resource production: {e}");
                Err(e)
            }
        }
    }
    .instrument(span)
    .boxed()
}

fn produce_resource_detect_recursion(rp_op: &Arc<RpOp>) -> Result<(), ResourceProductionError> {
    let trace_display_ridfmt = trace_display(rp_op.requested_ridfmt());

    let mut opt_recursion_detected_level = None;
    {
        let mut level = 0_usize;
        let mut op = rp_op.clone();
        loop {
            if 10 < level {
                warn!(
                    rf = rp_op.trace_field_rf(),
                    "deep resource production op recursion: op.target={:?}, rp_op.target={:?}",
                    op.requested_ridfmt(),
                    rp_op.requested_ridfmt()
                );
            }

            if 0 < level && op.requested_ridfmt() == rp_op.requested_ridfmt() {
                opt_recursion_detected_level = Some(level);
            }

            if let Some(outer_op) = op.as_ref().opt_outer_op() {
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
        let mut op = rp_op.clone();
        loop {
            let mut s = op.requested_ridfmt().abbreviation().into_owned();
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
    warn!(
        rf = rp_op.trace_field_rf(),
        "Recursion detected during resource production: {chain}"
    );

    Err(ResourceProductionError::RecursionDetected {
        ridfmt_request: rp_op.requested_ridfmt().into_owned(),
        chain,
    })
}

async fn produce_resource_from_producers(rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
    let trace_display_ridfmt = trace_display(rp_op.requested_ridfmt());
    // Try each registered ResourceProducer in order, returning the first result.
    trace!(
        rf = rp_op.trace_field_rf(),
        "Iterating registrations vvvvvvvvvvvvvvvvvvvvvvvvvvvv"
    );
    for registryentry in rp_op
        .eg()
        .config()
        .resourceproducer_registry()
        .registrations()
    {
        trace!(
            rf = rp_op.trace_field_rf(),
            "Provider registry entry: {registryentry:?}"
        );

        let arc_resource_producer = registryentry.get_or_create_resourceproducer();

        trace!(
            rf = rp_op.trace_field_rf(),
            "-- obtained {arc_resource_producer:?}"
        );

        let opt_result = arc_resource_producer.maybe_produce(rp_op);

        if opt_result.is_some() {
            opt_result.as_ref().inspect(|&result| {
                debug!(
                    rf = rp_op.trace_field_rf(),
                    "resource_producer.maybe_produce() -> `Some`: {result:?}"
                );
            });

            // This provider has yielded a result, return it.
            return opt_result;
        }
    }
    trace!(
        rf = rp_op.trace_field_rf(),
        "Iterating registrations ^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    );

    None
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{Context, Result, anyhow, bail, ensure};
    use insta::assert_ron_snapshot;

    use super::*;
    use crate::eg_config::EgConfig;
    use crate::resource::ElectionDataObjectId;

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::resource_production::t::t1",
            );

            // Failure cases where we don't have a ResourceProducer set up to handle the request.

            let rid_edo_pvd = ResourceId::ElectionDataObject(ElectionDataObjectId::PreVotingData);
            assert_ron_snapshot!(eg.produce_resource(
            &ResourceIdFormat {
                rid: rid_edo_pvd.clone(),
                fmt: ResourceFormat::SliceBytes,
            }
        ).await.err(), @r#"
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
        ).await.err(), @r#"
        Some(NoProducerFound(
          ridfmt: ResourceIdFormat(
            rid: ElectionDataObject(PreVotingData),
            fmt: ConcreteType,
          ),
        ))
        "#);
        });
    }
}
