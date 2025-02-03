// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::{any, rc::Rc};

use anyhow::{anyhow, bail};
use either::Either;
use serde::{Deserialize, Serialize};

use crate::{
    eg::Eg,
    election_manifest::{ElectionManifest, ElectionManifestInfo},
    election_parameters::{ElectionParameters, ElectionParametersInfo},
    errors::{EgError, EgResult},
    extended_base_hash::ExtendedBaseHash_H_E,
    guardian::GuardianKeyPurpose,
    hashes::Hashes,
    joint_public_key::JointPublicKey,
    serializable::SerializableCanonical,
    validatable::Validated,
};

//? TODO this structure can go away completey as it is redundant
#[derive(Debug, Clone)]
pub struct PreVotingDataInfo {
    /// Baseline election and cryptographic parameters.
    pub election_parameters: Either<Rc<ElectionParametersInfo>, Rc<ElectionParameters>>,

    /// The election manifest.
    pub election_manifest: Either<Rc<ElectionManifestInfo>, Rc<ElectionManifest>>,

    /// Hashes H_P, H_M, H_B.
    pub hashes: Rc<Hashes>,

    /// "The joint vote encryption public key K"
    pub jvepk_k: Rc<JointPublicKey>,

    /// "The joint ballot data encryption public key ̂K" (K hat)
    pub jbdepk_k_hat: Rc<JointPublicKey>,

    /// Hash H_E.
    pub h_e: ExtendedBaseHash_H_E,
}

impl<'de> Deserialize<'de> for PreVotingDataInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use strum::{IntoStaticStr, VariantNames};
        use Either::*;

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
                    election_parameters: Left(Rc::new(election_parameters_info)),
                    election_manifest: Left(Rc::new(election_manifest_info)),
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
    src: PreVotingDataInfo, eg => EgResult<PreVotingData> {
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
                let election_parameters = ElectionParameters::try_validate_from_rc(election_parameters_info, eg)?;
                Rc::new(election_parameters)
            }
            Right(election_parameters) => election_parameters,
        };

        //----- Validate `election_manifest`.

        let election_manifest = match election_manifest {
            Left(election_manifest_info) => {
                let election_manifest = ElectionManifest::try_validate_from_rc(election_manifest_info, eg)?;
                Rc::new(election_manifest)
            }
            Right(rc_election_manifest) => rc_election_manifest,
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
    election_parameters: Rc<ElectionParameters>,

    #[serde(rename = "election_manifest")]
    election_manifest: Rc<ElectionManifest>,

    hashes: Rc<Hashes>,

    jvepk_k: Rc<JointPublicKey>,

    jbdepk_k_hat: Rc<JointPublicKey>,

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
    pub fn compute(eg: &Eg) -> EgResult<PreVotingData> {
        let election_parameters = eg.election_parameters()?;
        let election_manifest = eg.election_manifest()?;
        let hashes = eg.hashes()?;
        let jvepk_k = eg.joint_vote_encryption_public_key_k()?;
        let jbdepk_k_hat = eg.joint_ballot_data_encryption_public_key_k_hat()?;
        let h_e = eg.extended_base_hash()?.h_e().clone();

        let pre_voting_data_info = PreVotingDataInfo {
            election_parameters: Either::Right(election_parameters),
            election_manifest: Either::Right(election_manifest),
            hashes,
            jvepk_k,
            jbdepk_k_hat,
            h_e,
        };

        // This validation is expected to succeed, because PreVotingData is really just a collection.
        PreVotingData::try_validate_from(pre_voting_data_info, eg)
    }
}

impl SerializableCanonical for PreVotingData {}
