// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::{any, fmt::Debug, sync::Arc};

use anyhow::{anyhow, bail};
use either::Either;
use serde::{Deserialize, Serialize};

use crate::{
    election_manifest::{ElectionManifest, ElectionManifestInfo},
    election_parameters::{ElectionParameters, ElectionParametersInfo},
    errors::{EgError, EgResult},
    extended_base_hash::ExtendedBaseHash_H_E,
    guardian::GuardianKeyPurpose,
    hashes::Hashes,
    joint_public_key::JointPublicKey,
    resource::{
        ProduceResource, ProduceResourceExt, Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource_id::ElectionDataObjectId as EdoId,
    resource_producer::{ResourceProductionResult, ResourceSource, RpOp},
    resource_producer_registry::RPFnRegistration,
    resourceproducer_specific::GatherRPFnRegistrationsFnWrapper,
    serializable::SerializableCanonical,
    validatable::Validated,
};

//? TODO this structure can go away completey as it is redundant
#[derive(Debug, Clone)]
pub struct PreVotingDataInfo {
    /// Baseline election and cryptographic parameters.
    pub election_parameters: Either<Arc<ElectionParametersInfo>, Arc<ElectionParameters>>,

    /// The election manifest.
    pub election_manifest: Either<Arc<ElectionManifestInfo>, Arc<ElectionManifest>>,

    /// Hashes H_P, H_M, H_B.
    pub hashes: Arc<Hashes>,

    /// "The joint vote encryption public key K"
    pub jvepk_k: Arc<JointPublicKey>,

    /// "The joint ballot data encryption public key ̂K" (K hat)
    pub jbdepk_k_hat: Arc<JointPublicKey>,

    /// Hash H_E.
    pub h_e: ExtendedBaseHash_H_E,
}

impl PreVotingDataInfo {
    /// Computes the [`PreVotingDataInfo`] from gathered info.
    pub async fn compute(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<PreVotingDataInfo> {
        let election_parameters = produce_resource.election_parameters().await?;
        let election_manifest = produce_resource.election_manifest().await?;
        let hashes = produce_resource.hashes().await?;
        let jvepk_k = produce_resource
            .joint_vote_encryption_public_key_k()
            .await?;
        let jbdepk_k_hat = produce_resource
            .joint_ballot_data_encryption_public_key_k_hat()
            .await?;
        let h_e = produce_resource.extended_base_hash().await?.h_e().clone();

        let pre_voting_data_info = PreVotingDataInfo {
            election_parameters: Either::Right(election_parameters),
            election_manifest: Either::Right(election_manifest),
            hashes,
            jvepk_k,
            jbdepk_k_hat,
            h_e,
        };

        Ok(pre_voting_data_info)
    }
}

impl<'de> Deserialize<'de> for PreVotingDataInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use Either::*;
        use serde::de::{Error, MapAccess, Visitor};
        use strum::{IntoStaticStr, VariantNames};

        #[derive(Deserialize, IntoStaticStr, VariantNames)]
        #[serde(field_identifier)]
        #[allow(non_camel_case_types)]
        enum Field {
            election_parameters,
            election_manifest,
            hashes,
            jvepk_k,
            jbdepk_k_hat,
            extended_base_hash_h_e,
        }

        struct PreVotingDataInfoVisitor;

        impl<'de> Visitor<'de> for PreVotingDataInfoVisitor {
            type Value = PreVotingDataInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("PreVotingDataInfo")
            }

            fn visit_map<V>(self, mut map: V) -> Result<PreVotingDataInfo, V::Error>
            where
                V: MapAccess<'de>,
            {
                let Some((Field::election_parameters, election_parameters_info)) =
                    map.next_entry()?
                else {
                    return Err(V::Error::missing_field(Field::election_parameters.into()));
                };

                let Some((Field::election_manifest, election_manifest_info)) =
                    map.next_entry::<_, ElectionManifestInfo>()?
                else {
                    return Err(V::Error::missing_field(Field::election_manifest.into()));
                };

                let Some((Field::hashes, hashes)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::hashes.into()));
                };

                let Some((Field::jvepk_k, jvepk_k)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::jvepk_k.into()));
                };

                let Some((Field::jbdepk_k_hat, jbdepk_k_hat)) = map.next_entry()? else {
                    return Err(V::Error::missing_field(Field::jbdepk_k_hat.into()));
                };

                let Some((Field::extended_base_hash_h_e, extended_base_hash_h_e)) =
                    map.next_entry()?
                else {
                    return Err(V::Error::missing_field(
                        Field::extended_base_hash_h_e.into(),
                    ));
                };

                Ok(PreVotingDataInfo {
                    election_parameters: Left(Arc::new(election_parameters_info)),
                    election_manifest: Left(Arc::new(election_manifest_info)),
                    hashes,
                    jvepk_k,
                    jbdepk_k_hat,
                    h_e: extended_base_hash_h_e,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("PreVotingData", FIELDS, PreVotingDataInfoVisitor)
    }
}

crate::impl_knows_friendly_type_name! { PreVotingDataInfo }

crate::impl_MayBeResource_for_non_Resource! { PreVotingDataInfo } //? TODO impl Resource

crate::impl_validatable_validated! {
    src: PreVotingDataInfo, produce_resource => EgResult<PreVotingData> {
        use Either::*;

        let PreVotingDataInfo {
            election_parameters,
            election_manifest,
            hashes,
            jvepk_k,
            jbdepk_k_hat,
            h_e,
        } = src;

        //----- Validate `election_parameters`.

        let election_parameters = match election_parameters {
            Left(election_parameters_info) => {
                let election_parameters = ElectionParameters::try_validate_from_arc(election_parameters_info, produce_resource)?;
                Arc::new(election_parameters)
            }
            Right(election_parameters) => election_parameters,
        };

        //----- Validate `election_manifest`.

        let election_manifest = match election_manifest {
            Left(election_manifest_info) => {
                let election_manifest = ElectionManifest::try_validate_from_arc(election_manifest_info, produce_resource)?;
                Arc::new(election_manifest)
            }
            Right(arc_election_manifest) => arc_election_manifest,
        };

        //----- Validate `hashes`.

        //? TODO let hashes = hashes.re_validate()?;

        //----- Validate `joint_public_key`.

        //? TODO let joint_public_key = joint_public_key.re_validate(&election_parameters)?;

        //----- Validate `extended_base_hash`.

        //? TODO let extended_base_hash = extended_base_hash.re_validate()?;

        //----- Construct and return the object from the validated data.

        Ok(PreVotingData {
            election_parameters,
            election_manifest,
            hashes,
            jvepk_k,
            jbdepk_k_hat,
            h_e,
        })
    }
}

impl From<PreVotingData> for PreVotingDataInfo {
    /// Convert from PreVotingData back to a PreVotingDataInfo for re-validation.
    fn from(src: PreVotingData) -> Self {
        use Either::*;

        let PreVotingData {
            election_parameters,
            election_manifest,
            hashes,
            jvepk_k,
            jbdepk_k_hat,
            h_e: extended_base_hash,
        } = src;

        PreVotingDataInfo {
            election_parameters: Right(election_parameters),
            election_manifest: Right(election_manifest),
            hashes,
            jvepk_k,
            jbdepk_k_hat,
            h_e: extended_base_hash,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PreVotingData {
    #[serde(rename = "election_parameters")]
    election_parameters: Arc<ElectionParameters>,

    #[serde(rename = "election_manifest")]
    election_manifest: Arc<ElectionManifest>,

    hashes: Arc<Hashes>,

    jvepk_k: Arc<JointPublicKey>,

    jbdepk_k_hat: Arc<JointPublicKey>,

    h_e: ExtendedBaseHash_H_E,
}

crate::impl_knows_friendly_type_name! { PreVotingData }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { PreVotingData, PreVotingData }

impl PreVotingData {
    pub fn election_parameters(&self) -> &ElectionParameters {
        &self.election_parameters
    }

    pub fn election_manifest(&self) -> &ElectionManifest {
        &self.election_manifest
    }

    pub fn hashes(&self) -> &Hashes {
        &self.hashes
    }

    pub fn jvepk_k(&self) -> &JointPublicKey {
        self.jvepk_k.as_ref()
    }

    pub fn jbdepk_k_hat(&self) -> &JointPublicKey {
        self.jbdepk_k_hat.as_ref()
    }

    pub fn h_e(&self) -> &ExtendedBaseHash_H_E {
        &self.h_e
    }

    /// Computes the [`PreVotingData`].
    pub async fn compute(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<PreVotingData> {
        let pre_voting_data_info = PreVotingDataInfo::compute(produce_resource).await?;

        // This validation is expected to succeed, because PreVotingData is really just a collection.
        PreVotingData::try_validate_from(pre_voting_data_info, produce_resource)
    }
}

impl SerializableCanonical for PreVotingData {}

//=================================================================================================|

#[allow(non_upper_case_globals)]
const RID_PreVotingData: ResourceId = ResourceId::ElectionDataObject(EdoId::PreVotingData);

#[allow(non_upper_case_globals)]
const RIDFMT_PreVotingData_ValidatedEdo: ResourceIdFormat = ResourceIdFormat {
    rid: RID_PreVotingData,
    fmt: ResourceFormat::ValidElectionDataObject,
};

#[allow(non_snake_case)]
fn maybe_produce_PreVotingData_ValidatedEdo(rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
    Some(produce_PreVotingData_ValidatedEdo(rp_op))
}

#[allow(non_snake_case)]
fn produce_PreVotingData_ValidatedEdo(rp_op: &Arc<RpOp>) -> ResourceProductionResult {
    rp_op.check_ridfmt(&RIDFMT_PreVotingData_ValidatedEdo)?;

    let pre_voting_data = async_global_executor::block_on(PreVotingData::compute(rp_op.as_ref()))?;

    //? TODO 'depersisted' is not true
    let rpsrc = ResourceSource::validly_extracted_from(ResourceSource::TodoItsComplicated);
    Ok((Arc::new(pre_voting_data), rpsrc))
}

//=================================================================================================|

fn gather_rpspecific_registrations(register_fn: &mut dyn FnMut(RPFnRegistration)) {
    register_fn(RPFnRegistration::new_defaultproducer(
        RIDFMT_PreVotingData_ValidatedEdo,
        Box::new(maybe_produce_PreVotingData_ValidatedEdo),
    ));
}

inventory::submit! {
    GatherRPFnRegistrationsFnWrapper(gather_rpspecific_registrations)
}

//=================================================================================================|
