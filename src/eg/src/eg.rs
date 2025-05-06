// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::new_without_default)]
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

use std::{
    any::Any,
    cell::RefCell,
    collections::BTreeMap,
    pin::Pin,
    sync::{Arc, Weak},
};

use futures_lite::future::{self as fut_lite, FutureExt};
use serde::Serialize;
use static_assertions::{assert_impl_all, assert_obj_safe};
use tracing::{
    Instrument, debug, debug_span, error, info, info_span, instrument, trace, trace_span, warn,
};
use util::{
    abbreviation::Abbreviation,
    csprng::{Csprng, CsprngBuilder},
    csrng::{Csrng, DeterministicCsrng},
    vec1::Vec1,
};

pub use crate::eg_config::EgConfig;
use crate::{
    errors::{EgError, EgResult},
    guardian::GuardianKeyPartId,
    guardian_public_key::GuardianPublicKey,
    guardian_secret_key::GuardianIndex,
    joint_public_key::JointPublicKey,
    key::{AsymmetricKeyPart, KeyPurpose},
    resource::{
        ElectionDataObjectId as EdoId, ProduceResource, ProduceResourceExt, ProductionBudget,
        Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource_producer::{ResourceProductionError, ResourceProductionResult, ResourceSource},
    resource_production::{RpOp, produce_resource_impl_},
    resources::Resources,
    varying_parameters::VaryingParameters,
};

//=================================================================================================|

#[derive(Debug)]
pub struct Eg {
    weak_self: Weak<Self>,
    config: Arc<EgConfig>,
    csrng: DeterministicCsrng,
    resources: Arc<Resources>,
}

impl Eg {
    /// Creates an [`Eg`] with a default configuration.
    pub fn new() -> Arc<Self> {
        let config = EgConfig::new();
        Eg::from_config(config)
    }

    /// Creates a new [`Eg`] from an [`EgConfig`].
    #[inline]
    pub fn from_config(config: EgConfig) -> Arc<Self> {
        let arc_config = Arc::new(config);
        Eg::from_rc_config(arc_config)
    }

    /// Creates a new [`Eg`] from an [`Arc<EgConfig>`].
    pub fn from_rc_config(config: Arc<EgConfig>) -> Arc<Self> {
        let csprng = config.make_csprng_builder().finish();

        Arc::new_cyclic(|w| Self {
            weak_self: w.clone(),
            config,
            csrng: DeterministicCsrng::new(csprng),
            resources: Resources::new(),
        })
    }

    #[cfg(any(feature = "eg-allow-insecure-deterministic-csprng", test))]
    pub fn new_with_insecure_deterministic_csprng_seed<S: AsRef<str>>(
        insecure_deterministic_seed_str: S,
    ) -> Arc<Self> {
        let mut config = EgConfig::new();
        config.use_insecure_deterministic_csprng_seed_str(insecure_deterministic_seed_str);
        Self::from_config(config)
    }

    #[cfg(any(feature = "eg-allow-insecure-deterministic-csprng", test))]
    pub fn new_with_insecure_deterministic_csprng_seed_data<D: AsRef<[u8]>>(
        insecure_deterministic_seed_data: D,
    ) -> Arc<Self> {
        let mut config = EgConfig::new();
        config.use_insecure_deterministic_csprng_seed_data(insecure_deterministic_seed_data);
        Self::from_config(config)
    }

    #[cfg(any(
        all(
            feature = "eg-allow-insecure-deterministic-csprng",
            feature = "eg-allow-test-data-generation"
        ),
        test
    ))]
    pub fn new_with_test_data_generation_and_insecure_deterministic_csprng_seed<S: AsRef<str>>(
        insecure_deterministic_seed_str: S,
    ) -> Arc<Self> {
        let mut config = EgConfig::new();
        config.use_insecure_deterministic_csprng_seed_str(insecure_deterministic_seed_str);
        config.enable_test_data_generation();
        Self::from_config(config)
    }

    /// Provides access to the [`Eg`] as [`Weak<Self>`].
    #[inline]
    pub fn weak_self(&self) -> Weak<Self> {
        self.weak_self.clone()
    }

    /// Maybe provides access to the [`Eg`] as [`Arc<Self>`].
    #[inline]
    pub fn opt_self(&self) -> Option<Arc<Self>> {
        self.weak_self.upgrade()
    }

    /// Provides access to the [`EgConfig`].
    #[inline]
    pub fn config(&self) -> &EgConfig {
        &self.config
    }

    /// Provides access to the [`Csrng`].
    #[inline]
    pub fn csrng(&self) -> &dyn Csrng {
        &self.csrng
    }

    /// Provides access to the [`Resources`].
    #[inline]
    pub fn resources(&self) -> &Arc<Resources> {
        &self.resources
    }

    /// Provides the specified resource. It will remain available from the cache.
    ///
    /// Returns:
    ///
    /// - `Ok(())` if the resource was newly inserted, or
    /// - `Err(...)` if the resource already existed in the cache.
    pub async fn provide_resource(&self, arc_dr: Arc<dyn Resource>) -> EgResult<()> {
        self.resources.provide_resource(arc_dr).await?;
        Ok(())
    }

    /// Provides the specified resource result for the specified [`ResourceIdFormat`]. It will
    /// remain available from the cache.
    ///
    /// Returns:
    ///
    /// - `Ok(())` if the result was newly inserted, or
    /// - `Err(...)` if the result already existed in the cache.
    pub async fn provide_resource_production_result(
        &self,
        ridfmt: &ResourceIdFormat,
        provided_result: ResourceProductionResult,
    ) -> EgResult<()> {
        self.resources
            .provide_resource_production_result(ridfmt, provided_result)
            .await?;
        Ok(())
    }
}

impl ProduceResource for Eg {
    fn csrng(&self) -> &dyn util::csrng::Csrng {
        &self.csrng
    }

    fn trait_impl_produce_resource_<'a>(
        &'a self,
        ridfmt: ResourceIdFormat,
        opt_prod_budget: Option<ProductionBudget>,
    ) -> Pin<Box<dyn Future<Output = ResourceProductionResult> + Send + 'a>> {
        let ridfmt = ridfmt.clone();
        let span = trace_span!(
            "<Eg as ProduceResource>::trait_impl_produce_resource_",
            rf = tracing::field::display(ridfmt.abbreviation())
        )
        .or_current();

        if let Some(self_) = self.opt_self() {
            let rp_op = RpOp::new(
                self_,
                self.resources.clone(),
                ridfmt,
                opt_prod_budget,
                Some(span),
                None,
            );
            produce_resource_impl_(rp_op).boxed()
        } else {
            let e = ResourceProductionError::ResourceNoLongerNeeded { ridfmt };
            error!("Eg lost all incoming references: {e}");
            std::future::ready(Err(e)).boxed()
        }
    }
}

impl serde::Serialize for Eg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::{Error, SerializeMap};

        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("config", &self.config)?;
        map.serialize_entry("csrng", &self.csrng)?;
        map.serialize_entry("resource_states", &self.resources)?;
        map.end()
    }
}

assert_impl_all!(Eg: Send, Sync);

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{Context, Result, anyhow, bail, ensure};
    use insta::assert_ron_snapshot;

    use super::*;

    #[test_log::test]
    fn t1() {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::eg::t::t1",
        );

        assert_ron_snapshot!(eg, @r#"
        {
          "config": EgConfig(
            rpregistry: ResourceProducerRegistry(
              map: {
                RPRegistryEntry_Key(
                  name: "ExampleData",
                  category: DefaultProducer,
                ): RPRegistryEntry_Value(
                  arc_key: RPRegistryEntry_Key(
                    name: "ExampleData",
                    category: DefaultProducer,
                  ),
                  opt_arc_rp: Some(ResourceProducer_ExampleData(
                    n: 5,
                    k: 3,
                  )),
                ),
                RPRegistryEntry_Key(
                  name: "PublicFromSecretKey",
                  category: DefaultProducer,
                ): RPRegistryEntry_Value(
                  arc_key: RPRegistryEntry_Key(
                    name: "PublicFromSecretKey",
                    category: DefaultProducer,
                  ),
                  opt_arc_rp: None,
                ),
                RPRegistryEntry_Key(
                  name: "Specific",
                  category: DefaultProducer,
                ): RPRegistryEntry_Value(
                  arc_key: RPRegistryEntry_Key(
                    name: "Specific",
                    category: DefaultProducer,
                  ),
                  opt_arc_rp: None,
                ),
                RPRegistryEntry_Key(
                  name: "ValidateToEdo",
                  category: DefaultProducer,
                ): RPRegistryEntry_Value(
                  arc_key: RPRegistryEntry_Key(
                    name: "ValidateToEdo",
                    category: DefaultProducer,
                  ),
                  opt_arc_rp: None,
                ),
              },
            ),
            opt_insecure_deterministic_seed_data: "65673A3A65673A3A743A3A7431",
          ),
          "csrng": "DeterministicCsrng",
          "resource_states": {
            "resource_states": {},
          },
        }
        "#);
    }
}
