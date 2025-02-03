// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
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

use std::{any::Any, cell::RefCell, collections::BTreeMap, rc::Rc};

use serde::Serialize;
use tracing::{debug, debug_span, error, info, info_span, instrument, trace, trace_span, warn};
use util::{abbreviation::Abbreviation, csprng::Csprng, csrng::Csrng, vec1::Vec1};

pub use crate::eg_config::EgConfig;
use crate::{
    errors::{EgError, EgResult},
    guardian::{AsymmetricKeyPart, GuardianKeyId, GuardianKeyPurpose},
    guardian_public_key::GuardianPublicKey,
    guardian_secret_key::GuardianIndex,
    joint_public_key::JointPublicKey,
    resource::{ElectionDataObjectId, Resource, ResourceFormat, ResourceId, ResourceIdFormat},
    resource_csrng::Resource_Csrng,
    resource_producer::{ResourceProductionError, ResourceProductionResult, ResourceSource},
    resource_production::{produce_resource_impl_, RpOp},
    varying_parameters::VaryingParameters,
};

//=================================================================================================|

pub(crate) type RsrcCacheMapKey = ResourceIdFormat;
pub(crate) type RsrcCacheMapValue = (Rc<dyn Resource>, ResourceSource);
pub(crate) type RsrcCacheMap = BTreeMap<RsrcCacheMapKey, RsrcCacheMapValue>;

//=================================================================================================|

#[derive(Clone, Debug)]
pub struct Eg {
    config: Rc<EgConfig>,
    rsrc_csrng: Rc<Resource_Csrng>,
    rsrc_cache: RefCell<RsrcCacheMap>,
}

impl Eg {
    /// Creates a new [`Eg`] from an [`EgConfig`].
    #[inline]
    pub fn from_config(config: EgConfig) -> Self {
        let rc_config = Rc::new(config);
        Eg::from_rc_config(rc_config)
    }

    /// Creates a new [`Eg`] from an [`Rc<EgConfig>`].
    pub fn from_rc_config(config: Rc<EgConfig>) -> Self {
        let rc_rsrc_csrng: Rc<Resource_Csrng> = Rc::new(Resource_Csrng::new(&config));
        let rc_rsrc_csrng_dyn: Rc<dyn Resource> = rc_rsrc_csrng.clone();

        // Preload the cache with the provided resource.
        let mut rsrc_cache = [(
            rc_rsrc_csrng_dyn.ridfmt().clone(),
            (rc_rsrc_csrng_dyn, ResourceSource::Provided),
        )]
        .into_iter()
        .collect();

        Self {
            config,
            rsrc_csrng: rc_rsrc_csrng,
            rsrc_cache: RefCell::new(rsrc_cache),
        }
    }

    #[cfg(any(feature = "eg-allow-insecure-deterministic-csprng", test))]
    pub fn new_with_insecure_deterministic_csprng_seed<S: AsRef<str>>(
        insecure_deterministic_seed_str: S,
    ) -> Self {
        let mut config = EgConfig::new();
        config.use_insecure_deterministic_csprng_seed_str(insecure_deterministic_seed_str);
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
    ) -> Self {
        let mut config = EgConfig::new();
        config.use_insecure_deterministic_csprng_seed_str(insecure_deterministic_seed_str);
        config.enable_test_data_generation();
        Self::from_config(config)
    }

    /// Provides access to the [`EgConfig`].
    #[inline]
    pub fn config(&self) -> &EgConfig {
        &self.config
    }

    /// Provides access to the [`Csrng`].
    #[inline]
    pub fn csrng(&self) -> &dyn Csrng {
        self.rsrc_csrng.as_csrng()
    }

    /// Provides the specified resource. It will be available later from the cache.
    /// Returns:
    ///
    /// - `Ok(())` if the resource was newly inserted, or
    /// - `Err(...)` if the resource already existed in the cache.
    ///
    /// Note that unlike other ways resources get added to the cache, this is considered
    /// a mutating operation.
    pub fn provide_resource(&mut self, rc_dr: Rc<dyn Resource>) -> EgResult<()> {
        use std::collections::btree_map::{Entry::*, OccupiedEntry, VacantEntry};

        let ridfmt = rc_dr.ridfmt();

        let resource_cache = self.rsrc_cache.get_mut();
        match resource_cache.entry(ridfmt.clone()) {
            Vacant(vacant_entry) => {
                vacant_entry.insert((rc_dr, ResourceSource::Provided));
                Ok(())
            }
            Occupied(occupied_entry) => {
                debug_assert_eq!(ridfmt, occupied_entry.get().0.ridfmt());
                let e = ResourceProductionError::ResourceAlreadyStored {
                    ridfmt: ridfmt.clone(),
                    source_of_existing: occupied_entry.get().1.clone(),
                };
                Err(e.into())
            }
        }
    }

    /// Attempts to produce the requested resource.
    pub fn produce_resource(&self, ridfmt: &ResourceIdFormat) -> ResourceProductionResult {
        let span = trace_span!(
            "produce",
            rf = tracing::field::display(ridfmt.abbreviation())
        );
        let _enter_span = span.enter();

        // Forward to implementation in other file.
        let mut rp_op = RpOp::new(ridfmt.clone(), &span, None);
        produce_resource_impl_(self, &mut rp_op)
    }

    /// Attempts to produce the requested resource.
    /// Returns just the Rc<dyn Resource>, to simplify the many cases where the caller
    /// isn't interested in the [`DRProductionSource`].
    #[inline]
    pub fn produce_resource_no_src(
        &self,
        ridfmt: &ResourceIdFormat,
    ) -> Result<Rc<dyn Resource>, ResourceProductionError> {
        let span = trace_span!(
            "produce",
            rf = tracing::field::display(ridfmt.abbreviation())
        );
        let _enter_span = span.enter();

        // Forward to implementation in other file.
        let mut rp_op = RpOp::new(ridfmt.clone(), &span, None);
        produce_resource_impl_(self, &mut rp_op).map(|(rc, _)| rc)
    }

    /// Attempts to produce the requested resource and downcast it as the specified type.
    /// Returns the `Rc<T>`.
    pub fn produce_resource_downcast<T: Resource + Any>(
        &self,
        ridfmt: &ResourceIdFormat,
    ) -> Result<(Rc<T>, ResourceSource), ResourceProductionError> {
        let span = trace_span!(
            "produce",
            rf = tracing::field::display(ridfmt.abbreviation())
        );
        let _enter_span = span.enter();

        // Forward to implementation in other file.
        let mut rp_op = RpOp::new(ridfmt.clone(), &span, None);
        let (rc, rsrc) = produce_resource_impl_(self, &mut rp_op)?;

        let downcast_result = rc.into_any_rc().downcast::<T>();

        match downcast_result {
            Err(rc) => {
                let e = ResourceProductionError::CouldntDowncastResource {
                    src_ridfmt: ridfmt.clone(),
                    src_type: format!("{:?}", rc.type_id()),
                    target_type: format!("{:?}", std::any::TypeId::of::<T>()),
                };
                error!("{e:?}");
                Err(e)
            }
            Ok(rc) => Ok((rc, rsrc)),
        }
    }

    /// Attempts to produce the requested resource and downcast it as the specified type.
    ///
    /// Returns just the `Rc<T>` without [source information](ResourceSource).
    #[inline]
    pub fn produce_resource_downcast_no_src<T: Resource + Any>(
        &self,
        ridfmt: &ResourceIdFormat,
    ) -> Result<Rc<T>, ResourceProductionError> {
        self.produce_resource_downcast::<T>(ridfmt)
            .map(|(rc, _)| rc)
    }

    #[allow(clippy::needless_lifetimes)] //? TODO: Remove temp development code
    pub(crate) fn resource_cache_try_borrow<'q>(
        &'q self,
    ) -> Result<std::cell::Ref<'q, RsrcCacheMap>, ResourceProductionError> {
        self.rsrc_cache
            .try_borrow()
            .map_err(|_e| ResourceProductionError::ResourceCacheAlreadyMutablyInUse)
    }

    #[allow(clippy::needless_lifetimes)] //? TODO: Remove temp development code
    pub(crate) fn resource_cache_try_borrow_mut<'q>(
        &'q self,
    ) -> Result<std::cell::RefMut<'q, RsrcCacheMap>, ResourceProductionError> {
        self.rsrc_cache
            .try_borrow_mut()
            .map_err(|_e| ResourceProductionError::ResourceCacheAlreadyMutablyInUse)
    }
}

impl From<EgConfig> for Eg {
    /// A [`Eg`] can always be made from a [`EgConfig`].
    #[inline]
    fn from(config: EgConfig) -> Self {
        Eg::from_config(config)
    }
}

impl From<&EgConfig> for Eg {
    /// A [`Eg`] can always be made from a [`&EgConfig`](EgConfig).
    #[inline]
    fn from(config: &EgConfig) -> Self {
        Eg::from_config(config.clone())
    }
}

impl From<Rc<EgConfig>> for Eg {
    /// A [`Eg`] can always be made from a [`Rc<EgConfig>`].
    #[inline]
    fn from(config: Rc<EgConfig>) -> Self {
        Eg::from_rc_config(config)
    }
}

impl From<&Rc<EgConfig>> for Eg {
    /// A [`Eg`] can always be made from a [`&Rc<EgConfig>`](Rc<EgConfig>).
    #[inline]
    fn from(config: &Rc<EgConfig>) -> Self {
        Eg::from_rc_config(config.clone())
    }
}

//=================================================================================================|

macro_rules! helper_method_validated_edo_type {
    { $method_name:ident, $edoid:ident, $concrete_dr_type:path } => {
        /// Convenience method to obtain a [`ElectionDataObjectId::$edoid:ident`].
        pub fn $method_name(&self) -> EgResult<Rc<$concrete_dr_type>> {
            let ridfmt = crate::resource::ElectionDataObjectId::$edoid.validated_type_ridfmt();
            self.produce_resource_downcast_no_src::<$concrete_dr_type>(&ridfmt)
            .map_err(Into::into)
        }
    };
}

impl Eg {
    helper_method_validated_edo_type!(
        fixed_parameters,
        FixedParameters,
        crate::fixed_parameters::FixedParameters
    );
    helper_method_validated_edo_type!(
        varying_parameters,
        VaryingParameters,
        crate::varying_parameters::VaryingParameters
    );
    helper_method_validated_edo_type!(
        election_parameters,
        ElectionParameters,
        crate::election_parameters::ElectionParameters
    );
    helper_method_validated_edo_type!(
        election_manifest,
        ElectionManifest,
        crate::election_manifest::ElectionManifest
    );
    helper_method_validated_edo_type!(hashes, Hashes, crate::hashes::Hashes);
    //? todo helper_method_validated_edo_type!(guardian_key_part, GuardianKeyPart(GuardianKeyId),

    //? TODO #[cfg(any(feature = "eg-allow-test-data-generation", test))] GeneratedTestDataVoterSelections(crate::hash::HValue),

    //? TODO   Ballot ?

    /// Provides the guardian public keys for the specified purpose.
    ///
    /// If any key part fails to load, the entire function returns `Err`.
    pub fn guardian_public_keys(
        &self,
        key_purpose: GuardianKeyPurpose,
    ) -> EgResult<Vec1<Rc<GuardianPublicKey>>> {
        let varying_parameters = self.varying_parameters()?;
        let varying_parameters = varying_parameters.as_ref();

        let n: GuardianIndex = varying_parameters.n();

        let mut v1 = Vec1::with_capacity(n.into());
        for guardian_ix in GuardianIndex::iter_range_inclusive(GuardianIndex::one(), n) {
            let guardian_key_id = GuardianKeyId {
                guardian_ix,
                key_purpose,
                asymmetric_key_part: AsymmetricKeyPart::Public,
            };
            let edoid = ElectionDataObjectId::GuardianKeyPart(guardian_key_id);
            let ridfmt = edoid.validated_type_ridfmt();
            let public_key = self
                .produce_resource_downcast_no_src::<GuardianPublicKey>(&ridfmt)
                .map_err(Into::<EgError>::into)?;
            v1.try_push(public_key)?;
        }

        Ok(v1)
    }

    /// Convenience method to obtain the "joint vote encryption public key K".
    pub fn joint_vote_encryption_public_key_k(&self) -> EgResult<Rc<JointPublicKey>> {
        self.joint_public_key(
            GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
        )
    }

    /// Convenience method to obtain the "joint ballot data encryption public key ̂K" (K hat).
    pub fn joint_ballot_data_encryption_public_key_k_hat(&self) -> EgResult<Rc<JointPublicKey>> {
        self.joint_public_key(GuardianKeyPurpose::Encrypt_Ballot_AdditionalFreeFormData)
    }

    /// Convenience method to obtain a [`JointPublicKey`] for the specified key purpose.
    ///
    /// Prefer to use [`joint_vote_encryption_public_key_k`] or [`joint_ballot_data_encryption_public_key_k_hat`]
    /// where possible.
    pub fn joint_public_key(
        &self,
        key_purpose: GuardianKeyPurpose,
    ) -> EgResult<Rc<JointPublicKey>> {
        if !key_purpose.forms_joint_public_key() {
            return Err(EgError::NoJointPublicKeyForPurpose { key_purpose });
        }

        let ridfmt = crate::resource::ElectionDataObjectId::JointPublicKey(key_purpose)
            .validated_type_ridfmt();

        Ok(self.produce_resource_downcast_no_src::<JointPublicKey>(&ridfmt)?)
    }

    helper_method_validated_edo_type!(
        extended_base_hash,
        ExtendedBaseHash,
        crate::extended_base_hash::ExtendedBaseHash
    );

    helper_method_validated_edo_type!(
        pre_voting_data,
        PreVotingData,
        crate::pre_voting_data::PreVotingData
    );

    /// Provides the guardian secret keys for the specified purpose.
    /// (Only available with feature `eg-allow-test-data-generation` or `cfg(test)`, and even
    /// then there is no guarantee this data will be accessible to the caller.)
    ///
    /// If any key part fails to load, the entire function returns `Err`.
    #[cfg(any(feature = "eg-allow-test-data-generation", test))]
    pub fn guardians_secret_keys(
        &self,
        key_purpose: GuardianKeyPurpose,
    ) -> EgResult<Vec1<Rc<crate::guardian_secret_key::GuardianSecretKey>>> {
        let varying_parameters = self.varying_parameters()?;
        let varying_parameters = varying_parameters.as_ref();

        let n: GuardianIndex = varying_parameters.n();

        let mut v1 = Vec1::with_capacity(n.into());
        for guardian_ix in GuardianIndex::iter_range_inclusive(GuardianIndex::one(), n) {
            let guardian_key_id = GuardianKeyId {
                guardian_ix,
                key_purpose,
                asymmetric_key_part: AsymmetricKeyPart::Secret,
            };
            let edoid = ElectionDataObjectId::GuardianKeyPart(guardian_key_id);
            let ridfmt = edoid.validated_type_ridfmt();
            let secret_key = self
                .produce_resource_downcast_no_src::<crate::guardian_secret_key::GuardianSecretKey>(
                    &ridfmt,
                )
                .map_err(Into::<EgError>::into)?;
            v1.try_push(secret_key)?;
        }

        Ok(v1)
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

        let resource_cache_summary: BTreeMap<ResourceIdFormat, ResourceSource> = {
            let resource_cache = self
                .rsrc_cache
                .try_borrow()
                .map_err(|e| S::Error::custom(e.to_string()))?;

            resource_cache
                .iter()
                .map(|(k, v)| {
                    let rps: ResourceSource = v.1.clone();
                    (k.clone(), rps)
                })
                .collect()
        };
        map.serialize_entry("resource_cache_summary", &resource_cache_summary)?;

        map.end()
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{anyhow, bail, ensure, Context, Result};
    use insta::assert_ron_snapshot;

    use super::*;

    #[test]
    fn t0() {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::eg::t::t0",
        );

        assert_ron_snapshot!(eg, @r#"
        {
          "config": EgConfig(
            rpregistry: ResourceProducerRegistry(
              map: {
                RPRegistryEntry_Key(
                  name: "ElectionParametersInfo",
                  category: DefaultProducer,
                ): RPRegistryEntry_Value(
                  rc_key: RPRegistryEntry_Key(
                    name: "ElectionParametersInfo",
                    category: DefaultProducer,
                  ),
                  opt_rc_rp: None,
                ),
                RPRegistryEntry_Key(
                  name: "ExampleData",
                  category: DefaultProducer,
                ): RPRegistryEntry_Value(
                  rc_key: RPRegistryEntry_Key(
                    name: "ExampleData",
                    category: DefaultProducer,
                  ),
                  opt_rc_rp: Some(ResourceProducer_ExampleData(
                    n: 5,
                    k: 3,
                  )),
                ),
                RPRegistryEntry_Key(
                  name: "Specific",
                  category: DefaultProducer,
                ): RPRegistryEntry_Value(
                  rc_key: RPRegistryEntry_Key(
                    name: "Specific",
                    category: DefaultProducer,
                  ),
                  opt_rc_rp: None,
                ),
                RPRegistryEntry_Key(
                  name: "ValidateToEdo",
                  category: DefaultProducer,
                ): RPRegistryEntry_Value(
                  rc_key: RPRegistryEntry_Key(
                    name: "ValidateToEdo",
                    category: DefaultProducer,
                  ),
                  opt_rc_rp: None,
                ),
              },
            ),
            opt_insecure_deterministic_seed_data: "65673A3A65673A3A743A3A7430",
          ),
          "resource_cache_summary": {
            ResourceIdFormat(
              rid: Csrng,
              fmt: ConcreteType,
            ): Provided,
          },
        }
        "#);
    }
}
