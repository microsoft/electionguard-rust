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
    rc::Rc,
    //str::FromStr,
    //sync::OnceLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
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

//=================================================================================================|

/// The plain fn type for creating a new [`ResourceProducer`].
pub type FnNewResourceProducer = fn() -> Rc<dyn ResourceProducer_Any_Debug_Serialize>;

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
    fn(&mut dyn FnMut(&[ResourceProducerRegistration]));

/// Wrapper type to identify the collection of [`RegisterResourceProducerFactoryFn`]s for
/// [`inventory`].
pub struct GatherResourceProducerRegistrationsFnWrapper(pub GatherResourceProducerRegistrationsFn);

inventory::collect!(GatherResourceProducerRegistrationsFnWrapper);

//=================================================================================================|

/// Dyn fn type for [`ResourceProducer::maybe_produce`].
pub type DynFnMaybeProduce = dyn Fn(&Eg, &mut RpOp) -> Option<ResourceProductionResult>;

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

    pub fn ridfmt(&self) -> &ResourceIdFormat {
        &self.ridfmt
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

//=================================================================================================|

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct RPRegistryEntry_Key {
    /// Human-readable name of the [`ResourceProducer`].
    pub name: Cow<'static, str>,

    /// The category of the [`ResourceProducer`] produced by this [`ResourceProducerProducer`].
    pub category: ResourceProducerCategory,
}

//=================================================================================================|

#[derive(Debug, serde::Serialize)]
pub struct RPRegistryEntry_Value {
    /// Reference to the key.
    pub rc_key: Rc<RPRegistryEntry_Key>,

    /// Function to produce a [`ResourceProducer`].
    #[serde(skip)]
    pub fn_rc_new: FnNewResourceProducer,

    /// An optional constructed [`ResourceProducer`].
    pub opt_rc_rp: Option<Rc<dyn ResourceProducer_Any_Debug_Serialize>>,
}

impl RPRegistryEntry_Value {
    /// Creates a new [`RPRegistryEntry_Value`] from a [`ResourceProducerRegistration`].
    pub fn from_rp_registration(rp_reg: &ResourceProducerRegistration) -> Rc<Self> {
        let key = RPRegistryEntry_Key {
            name: rp_reg.name.clone(),
            category: rp_reg.category,
        };

        let value = Self {
            rc_key: Rc::new(key),
            fn_rc_new: rp_reg.fn_rc_new,
            opt_rc_rp: None,
        };

        Rc::new(value)
    }

    /// Creates a new [`RPRegistryEntry_Value`] from a [`ResourceProducer`] constructed [`ResourceProducer`].
    pub fn from_rc_resourceproducer(
        rc_rp: Rc<dyn ResourceProducer_Any_Debug_Serialize>,
    ) -> Rc<Self> {
        let key = RPRegistryEntry_Key {
            name: rc_rp.name(),
            category: rc_rp.category(),
        };

        let value = Self {
            rc_key: Rc::new(key),
            fn_rc_new: rc_rp.fn_rc_new(),
            opt_rc_rp: Some(rc_rp),
        };

        Rc::new(value)
    }

    pub fn get_or_create_resourceproducer(&self) -> Rc<dyn ResourceProducer_Any_Debug_Serialize> {
        match &self.opt_rc_rp {
            Some(rc_rp) => {
                debug!(
                    "RPRegistryEntry {} retrieving existing ResourceProducer instance",
                    self.rc_key.name
                );
                rc_rp.clone()
            }
            None => {
                debug!(
                    "RPRegistryEntry {} creating new ResourceProducer",
                    self.rc_key.name
                );
                (self.fn_rc_new)()
            }
        }
    }
}
//=================================================================================================|

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ResourceProducerRegistry {
    /// The `ResourceProducerRegistration`s. These are collected statically.
    map: BTreeMap<Rc<RPRegistryEntry_Key>, Rc<RPRegistryEntry_Value>>,
}

impl ResourceProducerRegistry {
    /// Returns a new [`ResourceProducerRegistry`] with all the [`ResourceProducers`] for [`DefaultProducer`](ResourceProducerCategory::DefaultProducer) category provided by [`inventoried`](inventory) static registration functions
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
                    self.add_rp_registration(rp_registration);
                }
            }
        };

        for register_resource_producer_factory_fn_wrapper in
            inventory::iter::<GatherResourceProducerRegistrationsFnWrapper>
        {
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
    ) -> Option<Rc<RPRegistryEntry_Value>> {
        let rc_rpre_value: Rc<RPRegistryEntry_Value> =
            RPRegistryEntry_Value::from_rp_registration(rp_reg);
        self.add_rc_rpre_value(rc_rpre_value)
    }

    /// Registers a [`ResourceProducer`], obtaining registration information from the
    /// `ResourceProducer` itself.
    pub fn register_resourceproducer(
        &mut self,
        rc_rp: Rc<dyn ResourceProducer_Any_Debug_Serialize>,
    ) -> Option<Rc<RPRegistryEntry_Value>> {
        let rc_rpre_value = RPRegistryEntry_Value::from_rc_resourceproducer(rc_rp);
        self.add_rc_rpre_value(rc_rpre_value)
    }

    fn add_rc_rpre_value(
        &mut self,
        rc_value: Rc<RPRegistryEntry_Value>,
    ) -> Option<Rc<RPRegistryEntry_Value>> {
        use std::collections::btree_map::Entry::*;

        match self.map.entry(rc_value.rc_key.clone()) {
            Vacant(v) => {
                v.insert(rc_value);
                None
            }
            Occupied(o) => {
                // We coud replace the existing value here, but the `rc_rpre_value.rc_key` would not
                // be the same object as the key used in the map.
                let (_, rc_previous_value) = o.remove_entry();

                self.map.insert(rc_value.rc_key.clone(), rc_value);

                Some(rc_previous_value)
            }
        }
    }

    /// Iterates over the [`RPRegistryEntry_Value`]s.
    pub fn registrations(&self) -> impl std::iter::Iterator<Item = &RPRegistryEntry_Value> {
        self.map.values().map(|rc_val| rc_val.as_ref())
    }

    /// Retains only the [`RPRegistryEntry_Value`]s specified by the predicate.
    pub fn registrations_retain<F>(&mut self, f: F)
    where
        F: FnMut(&RPRegistryEntry_Key, &RPRegistryEntry_Value) -> bool,
    {
        let mut f = f;
        self.map.retain(|rc_key, rc_value| f(rc_key, rc_value))
    }
}

//=================================================================================================|
