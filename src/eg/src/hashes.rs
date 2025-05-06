// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::{
    algebra_utils::to_be_bytes_left_pad,
    eg::Eg,
    election_parameters::ElectionParameters,
    errors::EgResult,
    fixed_parameters::{FixedParametersTrait, FixedParametersTraitExt},
    hash::{HValue, eg_h},
    resource::{
        ProduceResource, ProduceResourceExt, Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource_id::ElectionDataObjectId as EdoId,
    resource_producer::{ResourceProductionResult, ResourceSource, RpOp, ValidReason},
    resource_producer_registry::RPFnRegistration,
    resourceproducer_specific::GatherRPFnRegistrationsFnWrapper,
    serializable::SerializableCanonical,
    standard_parameters::{
        EGDS_V2_1_0_RELEASED_STANDARD_PARAMS_P_LEN_BYTES,
        EGDS_V2_1_0_RELEASED_STANDARD_PARAMS_Q_LEN_BYTES,
    },
};

//=================================================================================================|

//? TODO Validatable

/// Parameter Base Hash
///
/// EGDS 2.1.0 Section 3.1.2 pg. 16 eq. 4
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterBaseHash {
    pub h_p: HValue,
}

impl ParameterBaseHash {
    pub fn compute(election_parameters: &ElectionParameters) -> Self {
        let fixed_parameters = election_parameters.fixed_parameters();
        let varying_parameters = election_parameters.varying_parameters();

        // H_V = 0x76322E312E30 | b(0, 26)
        let h_v: HValue = [
            // This is the UTF-8 encoding of "v2.1.0"
            0x76, 0x32, 0x2E, 0x31, 0x2E, 0x30, // Padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
        .into();

        let expected_len: usize = 1065; // EGDS 2.1.0 §3.1.2 pg. 74 eq. 4

        // v = 0x00 | b(p,512)| b(q,32) | b(g,512) | b(n,4) | b(k,4)
        let mut v = Vec::with_capacity(expected_len);
        v.push(0x00);
        v.extend_from_slice(
            to_be_bytes_left_pad(
                fixed_parameters.p(),
                EGDS_V2_1_0_RELEASED_STANDARD_PARAMS_P_LEN_BYTES,
            )
            .as_slice(),
        );
        v.extend_from_slice(
            to_be_bytes_left_pad(
                fixed_parameters.q(),
                EGDS_V2_1_0_RELEASED_STANDARD_PARAMS_Q_LEN_BYTES,
            )
            .as_slice(),
        );
        v.extend_from_slice(
            to_be_bytes_left_pad(
                fixed_parameters.g(),
                EGDS_V2_1_0_RELEASED_STANDARD_PARAMS_P_LEN_BYTES,
            )
            .as_slice(),
        );
        v.extend_from_slice(varying_parameters.n().get_one_based_4_be_bytes().as_slice());
        v.extend_from_slice(varying_parameters.k().get_one_based_4_be_bytes().as_slice());

        assert_eq!(v.len(), expected_len);

        let h_p = eg_h(&h_v, &v);

        Self { h_p }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes {
    /// Parameter base hash.
    pub h_p: HValue,

    /// Election base hash.
    pub h_b: HValue,
}

impl Hashes {
    /// Computes the [`Hashes`].
    pub async fn compute(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> EgResult<Hashes> {
        let election_parameters = produce_resource.election_parameters().await?;
        let election_parameters = election_parameters.as_ref();

        let election_manifest = produce_resource.election_manifest().await?;
        let election_manifest = election_manifest.as_ref();

        // Computation of the base parameter hash H_P.
        let h_p = ParameterBaseHash::compute(election_parameters).h_p;

        // Computation of the election base hash H_B.
        let h_b = {
            let mut v = vec![0x01];

            let mut v_manifest_bytes = election_manifest.to_canonical_bytes()?;
            let manifest_len = v_manifest_bytes.len();

            let expected_len = 5 + manifest_len; // EGDS 2.1.0 pg. 74, S3.1.4 (5)

            let manifest_len_u32 = u32::try_from(manifest_len)?;
            v.extend_from_slice(&manifest_len_u32.to_be_bytes());
            assert_eq!(v.len(), 1 + 4);

            v.append(&mut v_manifest_bytes);
            assert_eq!(v.len(), 1 + 4 + manifest_len);

            assert_eq!(v.len(), expected_len);

            eg_h(&h_p, &v)
        };

        Ok(Hashes { h_p, h_b })
    }

    /// Parameter base hash.
    pub fn h_p(&self) -> &HValue {
        &self.h_p
    }

    /// Election base hash.
    pub fn h_b(&self) -> &HValue {
        &self.h_b
    }
}

impl std::fmt::Debug for Hashes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str("Hashes {\n    h_p: ")?;
        std::fmt::Display::fmt(&self.h_p, f)?;
        f.write_str(",\n    h_b: ")?;
        std::fmt::Display::fmt(&self.h_b, f)?;
        f.write_str(" }")
    }
}

impl std::fmt::Display for Hashes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Debug::fmt(self, f)
    }
}

impl SerializableCanonical for Hashes {}

crate::impl_MayBeValidatableUnsized_for_non_ValidatableUnsized! { Hashes }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { Hashes, Hashes }

//=================================================================================================|

#[allow(non_upper_case_globals)]
const RID_Hashes: ResourceId = ResourceId::ElectionDataObject(EdoId::Hashes);

#[allow(non_upper_case_globals)]
const RIDFMT_Hashes_ValidatedEdo: ResourceIdFormat = ResourceIdFormat {
    rid: RID_Hashes,
    fmt: ResourceFormat::ValidElectionDataObject,
};

#[allow(non_snake_case)]
fn maybe_produce_Hashes_ValidatedEdo(rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
    Some(produce_Hashes_ValidatedEdo(rp_op))
}

#[allow(non_snake_case)]
fn produce_Hashes_ValidatedEdo(rp_op: &Arc<RpOp>) -> ResourceProductionResult {
    rp_op.check_ridfmt(&RIDFMT_Hashes_ValidatedEdo)?;

    let extended_base_hash = async_global_executor::block_on(Hashes::compute(rp_op.as_ref()))?;

    let arc: Arc<dyn Resource> = Arc::new(extended_base_hash);

    let rpsrc = ResourceSource::Valid(ValidReason::Inherent);
    Ok((arc, rpsrc))
}

//=================================================================================================|

fn gather_rpspecific_registrations(register_fn: &mut dyn FnMut(RPFnRegistration)) {
    register_fn(RPFnRegistration::new_defaultproducer(
        RIDFMT_Hashes_ValidatedEdo,
        Box::new(maybe_produce_Hashes_ValidatedEdo),
    ));
}

inventory::submit! {
    GatherRPFnRegistrationsFnWrapper(gather_rpspecific_registrations)
}

//=================================================================================================|

// Unit tests for the ElectionGuard hashes.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{Context, Result};
    use insta::assert_snapshot;

    use super::*;
    use crate::eg::Eg;

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            let eg = {
                let mut config = crate::eg::EgConfig::new();
                config.use_insecure_deterministic_csprng_seed_str("eg::hashes::t::t1");
                config.enable_test_data_generation_n_k(5, 3).unwrap();
                Eg::from_config(config)
            };
            let eg = eg.as_ref();

            let hashes = eg
                .hashes()
                .await
                .with_context(|| "Hashes::compute() failed")
                .unwrap();

            assert_snapshot!(hashes.h_p,
                @"944286970EAFDB6F347F4EB93B30D48FA3EDCC89BFBAEA6F5AE8F29AFB05DDCE");

            // This hash value has not been computed externally and will need to be modified
            // whenever the example data ElectionManifest changes.
            assert_snapshot!(hashes.h_b,
                @"D1AACAE2ABB43078D7903157D637B881618F3606387D6A9FD5CDF789E1DF5C4F");
        });
    }
}
