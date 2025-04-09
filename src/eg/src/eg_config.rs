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

use std::{
    any::Any,
    //borrow::Cow,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    //path::{Path, PathBuf},
    //str::FromStr,
    //sync::OnceLock,
    sync::Arc,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};
//use rand::{distr::Uniform, Rng, RngCore};
use serde::Serialize;
//use static_assertions::assert_obj_safe;
use static_assertions::const_assert;
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
use util::{
    csprng::{Csprng, CsprngBuilder},
    osrng::get_osrng_data_for_seeding,
};
use zeroize::Zeroizing;

use crate::{
    errors::{EgError, EgResult},
    guardian::GuardianIndex,
    resource::ResourceFormat,
    resource_producer::{
        ResourceProducer, ResourceProducer_Any_Debug_Serialize, ResourceProductionError,
    },
    resource_producer_registry::{
        FnNewResourceProducer, GatherResourceProducerRegistrationsFnWrapper,
        ResourceProducerCategory, ResourceProducerRegistration, ResourceProducerRegistry,
    },
    resourceproducer_exampledata::ResourceProducer_ExampleData,
    resourceproducer_exampledata::{EXAMPLE_DEFAULT_K, EXAMPLE_DEFAULT_N},
};

//=================================================================================================|

/// The entropy source for to the [`Csprng`](util::csprng::Csprng).
/// Values are arbitrary and not secret, chosen by `dd if=/dev/urandom | xxd -p -l16`.
#[derive(Clone, Copy)]
#[repr(u64)]
enum SeedMethod {
    TrueRandom = 0x2e5c3c94_8da12a07,

    #[cfg(any(feature = "eg-allow-insecure-deterministic-csprng", test))]
    InsecureDeterministic = 0x7d93b8b8_3ec23697,
}

//=================================================================================================|

#[derive(Clone, Debug, Default, Serialize)]
pub struct EgConfig {
    rpregistry: ResourceProducerRegistry,

    #[cfg(any(feature = "eg-allow-insecure-deterministic-csprng", test))]
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "util::serde::serialize_opt_bytes_as_uppercase_hex"
    )]
    opt_insecure_deterministic_seed_data: Option<Vec<u8>>,
}

impl EgConfig {
    /// Creates a new [`EgConfig`] with the default settings, including statically
    /// registered [default](ResourceProducerCategory::DefaultProducer) [`ResourceProducer`]s.
    pub fn new() -> EgConfig {
        Self {
            rpregistry: ResourceProducerRegistry::new_with_defaultproducers(),
            opt_insecure_deterministic_seed_data: None,
        }
    }

    /// `TESTING ONLY:` Use the specified string to initialize the Csprng for insecure fully-deterministic operation.
    #[cfg(any(feature = "eg-allow-insecure-deterministic-csprng", test))]
    #[inline]
    pub fn use_insecure_deterministic_csprng_seed_str<S: AsRef<str>>(
        &mut self,
        insecure_deterministic_csprng_seed_str: S,
    ) {
        self.use_insecure_deterministic_csprng_seed_data(
            insecure_deterministic_csprng_seed_str.as_ref().as_bytes(),
        );
    }

    /// `TESTING ONLY:` Use the specified string to initialize the Csprng for insecure fully-deterministic operation.
    #[cfg(any(feature = "eg-allow-insecure-deterministic-csprng", test))]
    #[inline]
    pub fn use_insecure_deterministic_csprng_seed_data<D: AsRef<[u8]>>(
        &mut self,
        insecure_deterministic_csprng_seed_data: D,
    ) {
        self.opt_insecure_deterministic_seed_data =
            Some(insecure_deterministic_csprng_seed_data.as_ref().into());
    }

    /// `TESTING ONLY:` Enable test data generation using the default settings.
    #[cfg(any(feature = "eg-allow-test-data-generation", test))]
    #[inline]
    pub fn enable_test_data_generation(&mut self) {
        let rp = ResourceProducer_ExampleData::default();
        let arc_rp = Arc::new(rp);
        self.rpregistry.register_resourceproducer(arc_rp);
    }

    /// `TESTING ONLY:` Enable test data generation using explicit values for `n` and `k`.
    /// Parameters `n` and `k` may be of any types that have a (possibly fallible) conversion to `GuardianIndex`.
    #[cfg(any(feature = "eg-allow-test-data-generation", test))]
    #[inline]
    pub fn enable_test_data_generation_n_k<N, K>(&mut self, n: N, k: K) -> EgResult<()>
    where
        N: TryInto<GuardianIndex>,
        K: TryInto<GuardianIndex>,
        EgError: From<<N as TryInto<GuardianIndex>>::Error>, // `?` uses `From`, see
        EgError: From<<K as TryInto<GuardianIndex>>::Error>, // https://github.com/rust-lang/rust/issues/38751#issuecomment-616573959
    {
        let n: GuardianIndex = n.try_into().map_err(EgError::from)?;
        let k: GuardianIndex = k.try_into().map_err(EgError::from)?;

        let rp = ResourceProducer_ExampleData::new_n_k(n, k);
        let arc_rp = Arc::new(rp);
        self.rpregistry.register_resourceproducer(arc_rp);

        Ok(())
    }

    /// The registry of [`ResourceProducer`]`s`.
    pub fn resourceproducer_registry(&self) -> &ResourceProducerRegistry {
        &self.rpregistry
    }

    /// Mutable access to the registry of [`ResourceProducer`]`s`.
    pub fn resourceproducer_registry_mut(&mut self) -> &mut ResourceProducerRegistry {
        &mut self.rpregistry
    }

    /// Returns a [`CsprngBuilder`](util::csprng::CsprngBuilder) for a new
    /// pre-loaded from the OS entropy source (or the provided insecure deterministic seed data),
    /// to be further customized or seeded.
    ///
    /// In insecure deterministic mode, if called multiple times with the same customization_data,
    /// an the same initialized Csprng will result.
    pub(crate) fn make_csprng_builder(&self) -> CsprngBuilder {
        #[cfg(any(feature = "eg-allow-insecure-deterministic-csprng", test))]
        if let Some(insecure_deterministic_seed_data) = &self.opt_insecure_deterministic_seed_data {
            info!(
                "Seeded CSPRNG builder with {} bytes of INSECURE DETERMINISTIC data.",
                insecure_deterministic_seed_data.len()
            );

            return Csprng::build()
                .write_u64(SeedMethod::InsecureDeterministic as u64)
                .write_bytes(insecure_deterministic_seed_data);
        }

        const CNT_BYTES_SEED_DATA: usize = Csprng::max_entropy_seed_bytes();
        const_assert!(crate::hash::HVALUE_BYTE_LEN <= CNT_BYTES_SEED_DATA);

        debug!(
            "Seeding CSPRNG builder with {CNT_BYTES_SEED_DATA} bytes of OS-provided true random data."
        );

        let mut true_random_seed_data = Zeroizing::new([0u8; CNT_BYTES_SEED_DATA]);
        get_osrng_data_for_seeding(&mut true_random_seed_data);

        info!(
            "Seeded CSPRNG builder with {} bytes of OS-provided true random data.",
            true_random_seed_data.len()
        );

        Csprng::build()
            .write_u64(SeedMethod::TrueRandom as u64)
            .write_bytes(true_random_seed_data)
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{Context, Result, anyhow, bail, ensure};
    use insta::assert_ron_snapshot;

    use super::*;

    #[test_log::test]
    fn t1() {
        let config = EgConfig::new();

        assert_ron_snapshot!(config,
            @r#"
        EgConfig(
          rpregistry: ResourceProducerRegistry(
            map: {
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
        )
        "#);
    }
}
