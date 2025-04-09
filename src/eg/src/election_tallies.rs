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
#![allow(unused_mut)]
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use serde::{Deserialize, Deserializer, Serialize};
use util::vec1::Vec1;

use crate::{
    contest_data_fields_tallies::ContestTallies,
    eg::Eg,
    election_manifest::{self, ElectionManifest},
    errors::EgResult,
    pre_voting_data,
    resource::{ProduceResource, ProduceResourceExt},
    serializable::SerializableCanonical,
};

/// Info for constructing a [`ElectionTallies`] through validation.
///
#[derive(Clone, Debug, Serialize)]
pub struct ElectionTalliesInfo {
    /// Tallies for each contest.
    pub contests: Vec1<ContestTallies>,
}

impl ElectionTalliesInfo {
    /// Creates an [`ElectionTalliesInfo`] having a zero-initialized entry for every contest as specified in a election_manifest.
    pub fn new_with_all_contests_zeroed(election_manifest: &ElectionManifest) -> EgResult<Self> {
        let mut contests =
            Vec1::<ContestTallies>::with_capacity(election_manifest.contests().len());
        for contest in election_manifest.contests().iter() {
            let zero_tallies = ContestTallies::new_zeroed_of_len(contest.qty_data_fields())?;
            contests.try_push(zero_tallies)?;
        }

        let self_ = ElectionTalliesInfo { contests };

        Ok(self_)
    }
}

impl<'de> Deserialize<'de> for ElectionTalliesInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use strum::{IntoStaticStr, VariantNames};

        #[derive(Deserialize, IntoStaticStr, VariantNames)]
        #[serde(field_identifier)]
        #[allow(non_camel_case_types)]
        enum Field {
            contests,
        }

        struct ElectionTalliesInfoVisitor;

        impl<'de> Visitor<'de> for ElectionTalliesInfoVisitor {
            type Value = ElectionTalliesInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("ElectionTalliesInfo")
            }

            fn visit_map<MapAcc>(
                self,
                mut map: MapAcc,
            ) -> Result<ElectionTalliesInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let Some((Field::contests, contests)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field("contests"));
                };

                Ok(ElectionTalliesInfo { contests })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("ElectionTallies", FIELDS, ElectionTalliesInfoVisitor)
    }
}

crate::impl_knows_friendly_type_name! { ElectionTalliesInfo }

crate::impl_Resource_for_simple_ElectionDataObjectId_info_type! { ElectionTalliesInfo, ElectionTallies }

impl SerializableCanonical for ElectionTalliesInfo {}

crate::impl_validatable_validated! {
    src: ElectionTalliesInfo, produce_resource => EgResult<ElectionTallies> {
        let election_parameters = produce_resource.election_parameters().await?.as_ref();
        let pre_voting_data = produce_resource.pre_voting_data().await?;
        let election_manifest = pre_voting_data.election_manifest();

        let ElectionTalliesInfo {
            contests,
        } = src;

        //----- Validate `contests`.

        // Verify that the number of contests is the same

        //----- Construct the object from the validated data.

        let self_ = Self {
            contests,
        };

        Ok(self_)
    }
}

impl From<ElectionTallies> for ElectionTalliesInfo {
    fn from(src: ElectionTallies) -> Self {
        let ElectionTallies { contests } = src;

        Self { contests }
    }
}

/// A complete set of tallies for an election. There is one for each contest, indexed by
/// [`ContestIndex`](crate::election_manifest::ContestIndex).
#[derive(
    Debug,
    Clone,
    derive_more::Deref,
    derive_more::DerefMut,
    derive_more::From,
    Serialize
)]
pub struct ElectionTallies {
    //? TODO ContestDataFieldsCiphertexts, ContestDataFieldsVerifiableDecryptions (See diagram)
    /// Tallies for each contest.
    contests: Vec1<ContestTallies>,
}

impl ElectionTallies {
    /// Tallies for each contest.
    pub fn contests(&self) -> &Vec1<ContestTallies> {
        &self.contests
    }
}

crate::impl_knows_friendly_type_name! { ElectionTallies }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { ElectionTallies, ElectionTallies }

impl SerializableCanonical for ElectionTallies {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{Context, anyhow, bail, ensure};

    use util::{csrng::Csrng, vec1::Vec1};

    use crate::{
        contest_data_fields_ciphertexts,
        eg::Eg,
        election_manifest,
        errors::{EgResult, EgValidateError},
        guardian_secret_key::GuardianSecretKey,
        resource::{ProduceResource, ProduceResourceExt},
        validatable::Validated,
    };

    use super::{ElectionTallies, ElectionTalliesInfo};

    async fn example_election_tallies_info(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<ElectionTalliesInfo> {
        let mut election_tallies_info = {
            let election_manifest = produce_resource.election_manifest().await?;
            let election_manifest = election_manifest.as_ref();
            ElectionTalliesInfo::new_with_all_contests_zeroed(election_manifest)?
        };

        {
            let csrng = produce_resource.csrng();

            for contest_tallies in election_tallies_info.contests.iter_mut() {
                for contest_data_field_tally in contest_tallies.iter_mut() {
                    // Pick a random tally that's roughly exponential with p=1/16 of 0 votes.
                    let tally = (0..3).fold(0, |tally, _| tally + csrng.next_u64().leading_zeros());
                    *contest_data_field_tally = tally.into();
                }
            }
        }

        Ok(election_tallies_info)
    }

    async fn example_election_tallies(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<ElectionTallies> {
        let election_tallies_info = example_election_tallies_info(produce_resource).await?;

        ElectionTallies::try_validate_from_async(produce_resource, election_tallies_info).await
    }

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::election_tallies::t::t1",
            );
            let eg = eg.as_ref();

            let election_tallies = example_election_tallies(eg).await.unwrap();

            assert!(false); //? TODO
        });
    }
}
