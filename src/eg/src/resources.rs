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

use std::{any::Any, pin::Pin, process::exit};
#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    borrow::{
        Cow,
        //Borrow,
    },
    //cell::RefCell,
    collections::{
        // BTreeSet,
        BTreeMap,
    },
    //collections::{HashSet, HashMap},
    //hash::{BuildHasher, Hash, Hasher},
    //io::{BufRead, Cursor},
    //iter::zip,
    //marker::PhantomData,
    //path::{Path, PathBuf},
    //process::ExitCode,
    //rc::Rc,
    //str::FromStr,
    sync::{
        Arc,
        //OnceLock,
    },
};

use async_lock::{
    RwLock,
    futures::{Read, Write},
};
//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
use futures_lite::future::{self, FutureExt};
use hashbrown::HashMap;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
use static_assertions::{assert_cfg, assert_impl_all, assert_obj_safe, const_assert};

use tracing::{
    debug, debug_span, error, field::display as trace_display, info, info_span, instrument, trace,
    trace_span, warn,
};
use util::abbreviation::Abbreviation;
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    errors::{EgError, EgResult, ResourceProductionError},
    resource_producer::{ResourceProductionOk, ResourceProductionResult},
};
#[rustfmt::skip] //? TODO: Remove temp development code
use crate::{
    resource::{Resource, ResourceIdFormat},
    resource_producer::ResourceSource,
};

//=================================================================================================|

pub(crate) type RsrcCacheMapKey = ResourceIdFormat;

//? TODO: Weak<RpOp> as part of map value
pub(crate) type RsrcCacheMapValue = ResourceProductionResult;

pub(crate) type RsrcCacheMap = BTreeMap<RsrcCacheMapKey, RsrcCacheMapValue>;

//-------------------------------------------------------------------------------------------------|

/// A cache and concurrent graph for handling
pub struct Resources {
    rsrc_cache: RwLock<RsrcCacheMap>,
}

impl Resources {
    // Makes a new default [`ResourceState`].
    pub fn new() -> Arc<Self> {
        let self_ = Self {
            rsrc_cache: RwLock::new(RsrcCacheMap::new()),
        };
        Arc::new(self_)
    }

    /// Provides the specified resource. It will remain available from the cache.
    /// Returns:
    ///
    /// - `Ok(())` if the resource was newly inserted, or
    /// - `Err(...)` if the resource already existed in the cache.
    pub async fn provide_resource(
        &self,
        arc_dr: Arc<dyn Resource>,
    ) -> Result<(), ResourceProductionError> {
        let ridfmt = arc_dr.ridfmt().clone();
        let provided_result_ok: ResourceProductionOk = (arc_dr, ResourceSource::Provided);
        let provided_result: ResourceProductionResult = Ok(provided_result_ok);

        self.record_rprod_result(&ridfmt, provided_result).await
    }

    /// Provides the specified resource. It will remain available from the cache.
    /// Returns:
    ///
    /// - `Ok(())` if the resource was newly inserted, or
    /// - `Err(...)` if the resource already existed in the cache.
    pub async fn provide_resource_production_result(
        &self,
        ridfmt: &ResourceIdFormat,
        provided_result: ResourceProductionResult,
    ) -> Result<(), ResourceProductionError> {
        self.record_rprod_result(ridfmt, provided_result).await
    }

    /// Obtains a cached [`ResourceProductionResult`], without doing any work to produce it.
    ///
    /// Returns:
    ///
    /// - `None` if the [`ResourceProductionResult`] is not in the cache.
    /// - `Some(ResourceProductionResult)` if the [`ResourceProductionResult`] has been cached.
    /// - `Some(Err(ResourceProductionError::ResourceCacheAlreadyMutablyInUse))` if the cache
    ///   is already mutably borrowed.
    pub async fn obtain_resource_production_result_from_cache(
        &self,
        ridfmt: &ResourceIdFormat,
    ) -> Option<ResourceProductionResult> {
        //? TODO Turn this into just a regular request with a production budget of Zero.
        let resource_cache = self.resource_cache_read().await;
        let opt_result = resource_cache.get(ridfmt);

        opt_result.map(|ref_result: &ResourceProductionResult| {
            let resource_production_result: ResourceProductionResult = match ref_result {
                Ok(pr) => {
                    let resource: Arc<dyn Resource + 'static> = pr.0.clone();
                    let mut resource_source: ResourceSource = pr.1.clone();
                    if resource_source.is_cache() {
                        resource_source = ResourceSource::Cache(Box::new(resource_source));
                    }
                    Ok((resource, resource_source))
                }
                Err(e) => Err(e.clone()),
            };
            resource_production_result
        })
    }

    /// Obtains a cached [`ResourceProductionResult`], without doing any work to produce it.
    /// If successful, it will attempt to downcast the result to the specified [`Resource`] type
    /// `T`.
    ///
    /// Returns:
    ///
    /// - `None` if the [`ResourceProductionResult`] is not in the cache.
    /// - `Some(Result<(Arc<T>, ResourceSource))` if the [`ResourceProductionResult`] has been
    ///   cached.
    /// - `Some(Err(ResourceProductionError::ResourceCacheAlreadyMutablyInUse))` if the cache
    ///   is already mutably borrowed.
    /// - `Some(Err(ResourceProductionError::CouldntDowncastResource))` if the dynamic downcast
    ///   did not succeed.
    ///
    pub async fn obtain_resource_production_result_from_cache_downcast<
        T: Resource + Any + 'static,
    >(
        &self,
        ridfmt: &ResourceIdFormat,
    ) -> Option<Result<(Arc<T>, ResourceSource), ResourceProductionError>> {
        //? TODO Turn this into just a regular request with a production budget of Zero.
        self.obtain_resource_production_result_from_cache(ridfmt)
            .await
            .map(|rp_result| {
                rp_result.and_then(|(arc_dyn_resource, resource_source)| {
                    let src_typename = std::any::type_name_of_val(arc_dyn_resource.as_ref());
                    let arc_dyn_any_send_sync = arc_dyn_resource.into_any_arc();
                    match arc_dyn_any_send_sync.downcast::<T>() {
                        Err(arc) => {
                            let src_type_expected = format!(
                                "{} {:?}",
                                std::any::type_name::<T>(),
                                std::any::TypeId::of::<T>()
                            );
                            let src_type_expected2 = src_type_expected.clone();
                            let e = ResourceProductionError::CouldntDowncastResource {
                                src_ridfmt: ridfmt.clone(),
                                src_resource_source: resource_source,
                                src_type: format!("{} {:?}", src_typename, arc.type_id()),
                                opt_src_type_expected: Some(src_type_expected),
                                target_type: src_type_expected2,
                            };
                            error!("obtain_resource_production_result_from_cache_downcast {e:?}");
                            Err(e)
                        }
                        Ok(arc) => Ok((arc, resource_source)),
                    }
                })
            })
    }

    /// Obtains a cached [`ResourceProductionResult`], without doing any work to produce it.
    /// If successful, it will attempt to downcast the result to the specified [`Resource`] type
    /// `T`.
    ///
    /// Returns just the `Arc<dyn Resource>`, to simplify the common case where the caller isn't
    /// interested in the [`ResourceSource`].
    ///
    /// Returns:
    ///
    /// - `None` if the [`ResourceProductionResult`] is not in the cache.
    /// - `Some(Result<Arc<T>>)` if the [`ResourceProductionResult`] has been cached.
    /// - `Some(Err(ResourceProductionError::ResourceCacheAlreadyMutablyInUse))` if the cache
    ///   is already mutably borrowed.
    /// - `Some(Err(ResourceProductionError::CouldntDowncastResource))` if the dynamic downcast
    ///   did not succeed.
    pub async fn obtain_resource_production_result_from_cache_downcast_no_src<
        T: Resource + Any + 'static,
    >(
        &self,
        ridfmt: &ResourceIdFormat,
    ) -> Option<Result<Arc<T>, ResourceProductionError>> {
        //? TODO this just becomes a regular request with a production budget of Zero
        self.obtain_resource_production_result_from_cache_downcast(ridfmt)
            .await
            .map(|result| result.map(|(arc, _)| arc))
    }

    pub(crate) fn resource_cache_get_mut(&mut self) -> &mut RsrcCacheMap {
        self.rsrc_cache.get_mut()
    }

    pub(crate) fn resource_cache_read(&self) -> Read<'_, RsrcCacheMap> {
        self.rsrc_cache.read()
    }

    pub(crate) fn resource_cache_write(&self) -> Write<'_, RsrcCacheMap> {
        self.rsrc_cache.write()
    }

    pub(crate) async fn record_rprod_result(
        &self,
        ridfmt: &ResourceIdFormat,
        resource_production_result: ResourceProductionResult,
    ) -> Result<(), ResourceProductionError> {
        use std::collections::btree_map::{Entry::*, OccupiedEntry, VacantEntry};

        let trace_field_rf = trace_display(ridfmt.abbreviation());

        // If the provided result contains a resource, check that it matches the resource ID provided by the caller.
        if let Ok((rpr_ok_arc, _rpr_ok_resource_source)) = &resource_production_result {
            let rpr_ok_resource_ridfmt = rpr_ok_arc.ridfmt();
            if ridfmt != rpr_ok_resource_ridfmt {
                let e = ResourceProductionError::UnexpectedResourceIdFormatProvided {
                    ridfmt_provided: ridfmt.clone(),
                    ridfmt_internal: rpr_ok_resource_ridfmt.clone(),
                };
                error!(rf = trace_field_rf, "{e:?}");
                Err(e)?
            }
        }

        let str_ok_err = if resource_production_result.is_ok() {
            "Ok"
        } else {
            "Err"
        };

        let mut resource_cache = self.resource_cache_write().await;
        match resource_cache.entry(ridfmt.clone()) {
            Vacant(vacant_entry) => {
                match &resource_production_result {
                    Ok((_rpr_ok_arc, rpr_ok_resource_source)) => {
                        info!(
                            rf = trace_field_rf,
                            "Recording for `{ridfmt}` a new `{str_ok_err}` result produced by `{rpr_ok_resource_source}`."
                        );
                    }
                    Err(e) => {
                        warn!(
                            rf = trace_field_rf,
                            "Recording for `{ridfmt}` a new `{str_ok_err}` result: {e:?}"
                        );
                    }
                }

                vacant_entry.insert(resource_production_result);
            }
            Occupied(mut occupied_entry) => {
                match occupied_entry.get() {
                    Ok((occupied_entry_arc, occupied_entry_resource_source)) => {
                        match &resource_production_result {
                            Ok((rpr_ok_arc, rpr_ok_resource_source)) => {
                                if Arc::ptr_eq(occupied_entry_arc, rpr_ok_arc) {
                                    // Somehow, between the time this production request was started
                                    // and now, this data resource (instance) got cached already.
                                    // Surprising, but not an error.
                                    debug!(
                                        rf = trace_field_rf,
                                        "For `{ridfmt}`, same `Ok` instance was already present in cache. The new instance was produced by `{rpr_ok_resource_source}`. Existing entry was produced by `{occupied_entry_resource_source}`."
                                    );
                                } else {
                                    debug!(
                                        rf = trace_field_rf,
                                        "For `{ridfmt}`, replacing `Ok` instance with new instance produced by `{rpr_ok_resource_source}`. Existing entry was produced by `{occupied_entry_resource_source}`."
                                    );
                                }
                            }
                            Err(rpr_err) => {
                                let e = ResourceProductionError::ResourceAlreadyStored {
                                    ridfmt: ridfmt.clone(),
                                    stored_resource_source: occupied_entry_resource_source.clone(),
                                    rpr_err: Box::new(rpr_err.clone()),
                                };
                                error!(rf = trace_field_rf, "{e:?}");
                                Err(e)?;
                            }
                        }
                    }
                    Err(ref_existing_e) => match &resource_production_result {
                        Ok((_rpr_ok_arc, rpr_ok_resource_source)) => {
                            debug!(
                                rf = trace_field_rf,
                                "For `{ridfmt}`, replacing Err({ref_existing_e:?}) with new `{str_ok_err}` result: {rpr_ok_resource_source}"
                            );
                        }
                        Err(e) => {
                            debug!(
                                rf = trace_field_rf,
                                "For `{ridfmt}`, replacing Err({ref_existing_e:?}) with new `{str_ok_err}` result: {e:?}"
                            );
                        }
                    },
                }
                let _ = occupied_entry.insert(resource_production_result);
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for Resources {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResourceState")
    }
}

impl std::fmt::Debug for Resources {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl serde::Serialize for Resources {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::{Error, SerializeMap};

        let mut map = serializer.serialize_map(Some(3))?;

        let resource_states: BTreeMap<Cow<'static, str>, &'static str> = {
            let resource_cache = self.rsrc_cache.read_blocking();
            resource_cache
                .iter()
                .map(|(ridfmt, resource_production_result)| {
                    let str_ok_err = if resource_production_result.is_ok() {
                        "Ok"
                    } else {
                        "Err"
                    };
                    (ridfmt.abbreviation(), str_ok_err)
                })
                .collect()
        };
        map.serialize_entry("resource_states", &resource_states)?;

        map.end()
    }
}

assert_impl_all!(Resources: Send, Sync);
