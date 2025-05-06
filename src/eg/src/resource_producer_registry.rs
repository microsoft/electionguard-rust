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
    resource::ResourceIdFormat,
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionError,
        ResourceProductionOk, ResourceProductionResult,
    },
    resource_production::RpOp,
};

//=================================================================================================|

/// Categories of [`ResourceProducer`].
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize
)]
pub enum ResourceProducerCategory {
    /// The [`ResourceProducer`] is appropriate for inclusion in the default configuration.
    DefaultProducer,

    /// The [`ResourceProducer`] generates test data and is intended to be used only for testing
    /// purposes.
    #[cfg(feature = "eg-allow-test-data-generation")]
    GeneratedTestData,
}

assert_impl_all!(ResourceProducerCategory: Send, Sync, Unpin);

//=================================================================================================|

/// The plain fn type for creating a new [`ResourceProducer`].
pub type FnNewResourceProducer = fn() -> Arc<dyn ResourceProducer_Any_Debug_Serialize + 'static>;

/// Implementations of [`ResourceProducer`]s register to express
/// (via [inventory::submit!] `{` [RegisterResourceProducerFactoryFnWrapper] `}`)
/// their ability to create a new [`ResourceProducer`] which MAY be able to produce
/// the described resources.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ResourceProducerRegistration {
    /// Human-readable name of the [`ResourceProducer`].
    pub name: Cow<'static, str>,

    /// The category of the [`ResourceProducer`].
    pub category: ResourceProducerCategory,

    /// Function to produce an instance of the [`ResourceProducer`].
    #[serde(skip)]
    pub fn_rc_new: FnNewResourceProducer,
}

impl ResourceProducerRegistration {
    /// Shorthand for creating a [`ResourceProducerFactoryRegistration`] expressing the
    /// [`DefaultProducer`](ResourceProducerCategory::DefaultProducer) category.
    pub fn new_defaultproducer<S: Into<Cow<'static, str>>>(
        name: S,
        fn_rc_new: FnNewResourceProducer,
    ) -> Self {
        Self {
            name: name.into(),
            category: ResourceProducerCategory::DefaultProducer,
            fn_rc_new,
        }
    }
}

/// The plain fn callback type allowing modules implementing [`ResourceProducer`]s to register
/// (via [inventory::submit!] `{` [RegisterResourceProducerFactoryFnWrapper] `}`)
/// their ability to create a new [`ResourceProducer`].
pub type GatherResourceProducerRegistrationsFn =
    fn(&mut dyn for<'a> FnMut(&'a [ResourceProducerRegistration]));

/// Wrapper type to identify the collection of [`RegisterResourceProducerFactoryFn`]s for
/// [`inventory`].
pub struct GatherResourceProducerRegistrationsFnWrapper(pub GatherResourceProducerRegistrationsFn);

assert_impl_all!(GatherResourceProducerRegistrationsFnWrapper: Send, Sync, Unpin);

inventory::collect!(GatherResourceProducerRegistrationsFnWrapper);

//=================================================================================================|

/// Dyn fn type for [`ResourceProducer::maybe_produce`].
pub type DynFnMaybeProduce = dyn Fn(&Arc<RpOp>) -> Option<ResourceProductionResult> + Send + Sync;

/// Boxed dyn fn type for [`ResourceProducer::maybe_produce`].
pub type BxDynFnMaybeProduce = Box<DynFnMaybeProduce>;

#[derive(serde::Serialize)]
pub struct RPFnRegistration {
    /// The [`ResourceProducer`] category for this rule.
    pub category: ResourceProducerCategory,

    /// The specific resource ID and format.
    pub ridfmt: ResourceIdFormat,

    //pub cost: i32,
    /// Function to produce an instance of the [`Resource`].
    #[serde(skip)]
    pub fn_maybe_produce: BxDynFnMaybeProduce,
}

impl RPFnRegistration {
    /// Shorthand for creating a [`RPFnRegistration`] expressing the
    /// [`DefaultProducer`](ResourceProducerCategory::DefaultProducer) category.
    pub fn new_defaultproducer(
        ridfmt: ResourceIdFormat,
        fn_maybe_produce: BxDynFnMaybeProduce,
    ) -> Self {
        Self {
            category: ResourceProducerCategory::DefaultProducer,
            ridfmt,
            //cost
            fn_maybe_produce,
        }
    }

    pub fn category(&self) -> ResourceProducerCategory {
        self.category
    }

    pub fn ridfmt(&self) -> Cow<'_, ResourceIdFormat> {
        Cow::Borrowed(&self.ridfmt)
    }

    //cost

    //fn_maybe_produce?
}

impl std::fmt::Debug for RPFnRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("RPFnRegistration");
        ds.field("category", &self.category);
        ds.field("ridfmt", &self.ridfmt);
        //ds.field("cost", &self.cost);
        ds.field("fn_maybe_produce", &"[fn]");
        ds.finish()
    }
}

assert_impl_all!(RPFnRegistration: Send, Sync, Unpin);

//=================================================================================================|

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct RPRegistryEntry_Key {
    /// Human-readable name of the [`ResourceProducer`].
    pub name: Cow<'static, str>,

    /// The category of the [`ResourceProducer`] produced by this [`ResourceProducerProducer`].
    pub category: ResourceProducerCategory,
}

assert_impl_all!(RPRegistryEntry_Key: Send, Sync, Unpin);

//=================================================================================================|

#[derive(Debug, serde::Serialize)]
pub struct RPRegistryEntry_Value {
    /// Reference to the key.
    pub arc_key: Arc<RPRegistryEntry_Key>,

    /// Function to produce a [`ResourceProducer`].
    #[serde(skip)]
    pub fn_rc_new: FnNewResourceProducer,

    /// An optional constructed [`ResourceProducer`].
    pub opt_arc_rp: Option<Arc<dyn ResourceProducer_Any_Debug_Serialize>>,
}

impl RPRegistryEntry_Value {
    /// Creates a new [`RPRegistryEntry_Value`] from a [`ResourceProducerRegistration`].
    pub fn from_rp_registration(rp_reg: &ResourceProducerRegistration) -> Arc<Self> {
        let key = RPRegistryEntry_Key {
            name: rp_reg.name.clone(),
            category: rp_reg.category,
        };

        let value = Self {
            arc_key: Arc::new(key),
            fn_rc_new: rp_reg.fn_rc_new,
            opt_arc_rp: None,
        };

        Arc::new(value)
    }

    /// Creates a new [`RPRegistryEntry_Value`] from a [`ResourceProducer`] constructed [`ResourceProducer`].
    pub fn from_rc_resourceproducer(
        arc_rp: Arc<dyn ResourceProducer_Any_Debug_Serialize + 'static>,
    ) -> Arc<Self> {
        let key = RPRegistryEntry_Key {
            name: arc_rp.name(),
            category: arc_rp.category(),
        };

        let value = Self {
            arc_key: Arc::new(key),
            fn_rc_new: arc_rp.fn_rc_new(),
            opt_arc_rp: Some(arc_rp),
        };

        Arc::new(value)
    }

    pub fn get_or_create_resourceproducer(
        &self,
    ) -> Arc<dyn ResourceProducer_Any_Debug_Serialize + 'static> {
        match &self.opt_arc_rp {
            Some(arc_rp) => {
                trace!(
                    "RPRegistryEntry {} retrieving existing ResourceProducer instance",
                    self.arc_key.name
                );
                arc_rp.clone()
            }
            None => {
                trace!(
                    "RPRegistryEntry {} creating new ResourceProducer",
                    self.arc_key.name
                );
                (self.fn_rc_new)()
            }
        }
    }
}

assert_impl_all!(RPRegistryEntry_Value: Send, Sync, Unpin);
assert_impl_all!(RPRegistryEntry_Value: Unpin);

//=================================================================================================|

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ResourceProducerRegistry {
    /// The `ResourceProducerRegistration`s. These are collected statically.
    map: BTreeMap<Arc<RPRegistryEntry_Key>, Arc<RPRegistryEntry_Value>>,
}

impl ResourceProducerRegistry {
    /// Returns a new [`ResourceProducerRegistry`] with all the [`ResourceProducers`] for
    /// [`DefaultProducer`](ResourceProducerCategory::DefaultProducer) category provided by
    /// [`inventoried`](inventory) static registration functions.
    pub fn new_with_defaultproducers() -> ResourceProducerRegistry {
        let mut self_ = Self::default();

        self_.add_static_registrations_conditionally(|rp_reg| {
            matches!(rp_reg.category, ResourceProducerCategory::DefaultProducer)
        });

        self_
    }

    /// Calls all the [`inventoried`](inventory) static registration functions and adds to the
    /// registry those for which `predicate` returns `true`.
    pub fn add_static_registrations_conditionally<P>(&mut self, mut predicate: P)
    where
        P: FnMut(&ResourceProducerRegistration) -> bool,
    {
        type FnMut_<'a> = &'a mut dyn for<'b> FnMut(&'b [ResourceProducerRegistration]);

        let f: FnMut_ = &mut |resource_producer_factory_registrations| {
            for rp_registration in resource_producer_factory_registrations {
                if predicate(rp_registration) {
                    debug!(
                        "ResourceProducerRegistry::add_static_registrations_conditionally: Adding {}",
                        rp_registration.name
                    );
                    self.add_rp_registration(rp_registration);
                } else {
                    debug!(
                        "ResourceProducerRegistry::add_static_registrations_conditionally: NOT adding {}",
                        rp_registration.name
                    );
                }
            }
        };

        for register_resource_producer_factory_fn_wrapper in
            inventory::iter::<GatherResourceProducerRegistrationsFnWrapper>
        {
            debug!(
                "ResourceProducerRegistry::add_static_registrations_conditionally: calling register_resource_producer_factory_fn_wrapper"
            );

            let register_resource_producer_factory_fn =
                register_resource_producer_factory_fn_wrapper.0;
            register_resource_producer_factory_fn(f);
        }
    }

    /// Adds a [`ResourceProducerRegistration`] to the registry.
    ///
    /// If the registry did not already have an entry matching this, None is returned.
    ///
    /// Any matching entry previously contained in the registry is removed and returned.
    pub fn add_rp_registration(
        &mut self,
        rp_reg: &ResourceProducerRegistration,
    ) -> Option<Arc<RPRegistryEntry_Value>> {
        let arc_rpregistry_entry_value: Arc<RPRegistryEntry_Value> =
            RPRegistryEntry_Value::from_rp_registration(rp_reg);
        self.add_rpregistry_entry_value(arc_rpregistry_entry_value)
    }

    /// Registers a [`ResourceProducer`], obtaining registration information from the
    /// `ResourceProducer` itself.
    pub fn register_resourceproducer(
        &mut self,
        arc_rp: Arc<dyn ResourceProducer_Any_Debug_Serialize + 'static>,
    ) -> Option<Arc<RPRegistryEntry_Value>> {
        let arc_rpregistry_entry_value = RPRegistryEntry_Value::from_rc_resourceproducer(arc_rp);
        self.add_rpregistry_entry_value(arc_rpregistry_entry_value)
    }

    fn add_rpregistry_entry_value(
        &mut self,
        arc_value: Arc<RPRegistryEntry_Value>,
    ) -> Option<Arc<RPRegistryEntry_Value>> {
        use std::collections::btree_map::Entry::*;

        let arc_key = arc_value.arc_key.clone();
        trace!(
            "ResourceProducerRegistry::add_rpregistry_entry_value: Adding entry {}",
            arc_key.name
        );

        match self.map.entry(arc_key) {
            Vacant(v) => {
                v.insert(arc_value);
                None
            }
            Occupied(o) => {
                // We could replace the existing value here, but the
                // `arc_rpregistry_entry_value.arc_key` would not  be the same object as the key
                // used in the map.
                let (_, arc_previous_value) = o.remove_entry();

                self.map.insert(arc_value.arc_key.clone(), arc_value);

                Some(arc_previous_value)
            }
        }
    }

    /// Iterates over the [`RPRegistryEntry_Value`]s.
    pub fn registrations(&self) -> impl std::iter::Iterator<Item = &RPRegistryEntry_Value> {
        self.map.values().map(|arc_val| arc_val.as_ref())
    }

    /// Retains only the [`RPRegistryEntry_Value`]s specified by the predicate.
    pub fn registrations_retain<F>(&mut self, f: F)
    where
        F: FnMut(&RPRegistryEntry_Key, &RPRegistryEntry_Value) -> bool,
    {
        debug!(
            "vvvvvvvvvvvvvvvvvvvv ResourceProducerRegistry::registrations_retain vvvvvvvvvvvvvvvvvvvv"
        );

        let mut f = f;
        self.map.retain(|arc_key, arc_value| {
            let keep = f(arc_key, arc_value);
            debug!(
                "{} {}",
                ["Discarding:", "Retaining: "][keep as usize],
                arc_key.name
            );
            keep
        });

        debug!(
            "^^^^^^^^^^^^^^^^^^^^ ResourceProducerRegistry::registrations_retain ^^^^^^^^^^^^^^^^^^^^"
        );
    }

    /// Emits debug-level log messages listing the current entries.
    pub fn debug_log_entries(&self) {
        let v: Vec<String> = self
            .registrations()
            .map(|rprev| format!("{rprev:?}"))
            .collect();
        let cnt = v.len();
        debug!(
            "vvvvvvvvvvvvvvvvvvvv ResourceProducerRegistry entries (N = {cnt}) vvvvvvvvvvvvvvvvvvvv"
        );
        for (ix0, s) in v.iter().enumerate() {
            let ix1 = ix0 + 1;
            debug!("ResourceProducerRegistry entry {ix1}/{cnt}: {s}");
        }
        debug!(
            "^^^^^^^^^^^^^^^^^^^^ ResourceProducerRegistry entries (N = {cnt}) ^^^^^^^^^^^^^^^^^^^^"
        );
    }
}

assert_impl_all!(ResourceProducerRegistry: Send, Sync, Unpin);

//=================================================================================================|
