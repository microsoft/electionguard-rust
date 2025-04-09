// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides the implementation of the [Joint Public Key](JointPublicKey)s
//! used for vote (K) and ballot data (K_hat) encryption.
//!
//! For more details see EGDS 2.1.0 sec. 3.2.2 pg. 26 eq. 25-26

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use num_bigint::BigUint;
use util::{
    algebra::{FieldElement, Group, GroupElement},
    index::IndexResult,
};

use util::algebra_utils::to_be_bytes_left_pad;

use crate::{
    ciphertext::Ciphertext,
    eg::Eg,
    election_parameters::ElectionParameters,
    errors::{EgError, EgResult, ResourceProductionError},
    fixed_parameters::FixedParameters,
    guardian::{GuardianIndex, GuardianKeyPurpose},
    guardian_public_key_trait::GuardianKeyInfoTrait,
    resource::{
        ProduceResource, ProduceResourceExt, Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource_id::ElectionDataObjectId as EdoId,
    resource_producer::{ResourceProductionResult, ResourceSource, RpOp, ValidReason},
    resource_producer_registry::RPFnRegistration,
    resourceproducer_specific::GatherRPFnRegistrationsFnWrapper,
    serializable::SerializableCanonical,
};

//=================================================================================================|

//? TODO Validatable

/// The joint election public key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct JointPublicKey {
    /// The [`GroupElement`].
    pub(crate) group_element: GroupElement,

    /// Refers to this object as a [`Resource`].
    /// Also, encodes the [`GuardianKeyPurpose`].
    #[serde(skip_serializing)]
    ridfmt: ResourceIdFormat,
}

impl JointPublicKey {
    /// [Key purpose](crate::guardian::GuardianKeyPurpose).
    pub fn key_purpose(&self) -> EgResult<GuardianKeyPurpose> {
        use ResourceId::ElectionDataObject;

        let ElectionDataObject(EdoId::JointPublicKey(key_purpose)) = self.ridfmt.rid else {
            return Err(EgError::UnexpectedResourceIdFormatForType {
                ridfmt: self.ridfmt.clone(),
                ty: "JointPublicKey",
            });
        };

        if !key_purpose.forms_joint_public_key() {
            return Err(EgError::NoJointPublicKeyForPurpose { key_purpose });
        }

        Ok(key_purpose)
    }

    /// The [`GroupElement`] used in asymmetric encryption operations.
    pub fn group_element(&self) -> &GroupElement {
        &self.group_element
    }

    /// Computes the [`JointPublicKey`].
    pub async fn compute(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        key_purpose: GuardianKeyPurpose,
    ) -> EgResult<JointPublicKey> {
        let election_parameters = produce_resource.election_parameters().await?;
        let election_parameters = election_parameters.as_ref();
        let fixed_parameters = election_parameters.fixed_parameters();
        let group = fixed_parameters.group();

        let varying_parameters = election_parameters.varying_parameters();
        let n = varying_parameters.n().get_one_based_usize();

        let gpks = produce_resource.guardian_public_keys(key_purpose).await?;
        let gpks = gpks.map_into(Arc::as_ref);

        // Validate every guardian public key against the election parameters.
        for &gpk in gpks.iter() {
            gpk.validate_public_key_info_to_election_parameters(produce_resource)
                .await?;
        }

        // Validate that every guardian is represented exactly once.
        let mut seen = vec![false; n];
        for &gpk in gpks.iter() {
            let seen_ix0 = gpk.i().get_zero_based_usize();

            if seen.get(seen_ix0).cloned().unwrap_or(true) {
                return Err(EgError::JointPublicKeyCompute_GuardianMultiple(gpk.i()));
            }

            seen[seen_ix0] = true;
        }

        let missing_guardian_ixs: Vec<GuardianIndex> = seen
            .iter()
            .enumerate()
            .filter(|&(_ix, &seen)| !seen)
            .map(|(ix0, _)| GuardianIndex::try_from_zero_based_index(ix0))
            .collect::<IndexResult<Vec<_>>>()?;

        if !missing_guardian_ixs.is_empty() {
            return Err(EgError::JointPublicKeyCompute_GuardiansMissing(
                missing_guardian_ixs,
            ));
        }

        let mut guardian_pub_keys_k_i_0 = vec![];
        for &gpk in gpks.iter() {
            guardian_pub_keys_k_i_0.push(gpk.public_key_k_i_0()?);
        }

        //  EGDS 2.1.0 sec. 3.2.2 pg. 26 eq. 25-26
        let jpk_group_elem = guardian_pub_keys_k_i_0
            .iter()
            .fold(Group::one(), |acc, &gpk_k_i_0| -> GroupElement {
                acc.mul(gpk_k_i_0, group)
            });

        let ridfmt = EdoId::JointPublicKey(key_purpose).validated_type_ridfmt();

        let self_ = Self {
            group_element: jpk_group_elem,
            ridfmt,
        };

        self_.validate(election_parameters)?;

        Ok(self_)
    }

    /// Encrypts a value to the joint election public key to produce a [`Ciphertext`].
    pub fn encrypt_to<T>(
        &self,
        fixed_parameters: &FixedParameters,
        nonce: &FieldElement,
        value: T,
    ) -> Ciphertext
    where
        BigUint: From<T>,
    {
        let field = fixed_parameters.field();
        let group = fixed_parameters.group();

        let alpha = group.g_exp(nonce);
        let exponent = &nonce.add(&FieldElement::from(value, field), field);
        let beta = self.group_element.exp(exponent, group);

        Ciphertext { alpha, beta }
    }

    /// Reads a `JointPublicKey` from a `std::io::Read` and validates it.
    // TODO goes away with Validatable Info
    pub fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        election_parameters: &ElectionParameters,
    ) -> Result<Self> {
        let self_: Self = serde_json::from_reader(stdioread).context("Reading JointPublicKey")?;

        self_.validate(election_parameters)?;

        Ok(self_)
    }

    /// Validates that the `JointPublicKey` conforms to the election parameters.
    // TODO goes away with Validatable Info
    pub fn validate(&self, election_parameters: &ElectionParameters) -> EgResult<()> {
        let key_purpose = self.key_purpose()?;
        let group = election_parameters.fixed_parameters().group();

        let valid = self.group_element.is_valid(group) && self.group_element != Group::one();

        if valid {
            Ok(())
        } else {
            Err(EgError::JointPublicKey_InvalidGroupElement(key_purpose))
        }
    }

    /// Returns the `JointPublicKey` as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_left_pad(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        let group = fixed_parameters.group();
        self.group_element.to_be_bytes_left_pad(group)
    }
}

impl SerializableCanonical for JointPublicKey {}

crate::impl_knows_friendly_type_name! { JointPublicKey }

crate::impl_MayBeValidatableUnsized_for_non_ValidatableUnsized! { JointPublicKey }

impl Resource for JointPublicKey {
    // Unwrap() is justified here because that expression is evaluated in the debug build only.
    #[allow(clippy::unwrap_used)]
    fn ridfmt(&self) -> &ResourceIdFormat {
        debug_assert_eq!(
            self.ridfmt,
            EdoId::JointPublicKey(self.key_purpose().unwrap()).validated_type_ridfmt()
        );
        &self.ridfmt
    }
}

//=================================================================================================|

#[allow(non_upper_case_globals)]
const JVEPK_K_KEY_PURPOSE: GuardianKeyPurpose =
    GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields;

#[allow(non_upper_case_globals)]
const JVEPK_K_EDOID: EdoId = EdoId::JointPublicKey(JVEPK_K_KEY_PURPOSE);

#[allow(non_upper_case_globals)]
const JVEPK_K_RID: ResourceId = ResourceId::ElectionDataObject(JVEPK_K_EDOID);

#[allow(non_upper_case_globals)]
const JVEPK_K_RIDFMT_ValidatedEdo: ResourceIdFormat = ResourceIdFormat {
    rid: JVEPK_K_RID,
    fmt: ResourceFormat::ValidElectionDataObject,
};

//=================================================================================================|

#[allow(non_upper_case_globals)]
const JVEPK_K_HAT_KEY_PURPOSE: GuardianKeyPurpose =
    GuardianKeyPurpose::Encrypt_Ballot_AdditionalFreeFormData;

#[allow(non_upper_case_globals)]
const JVEPK_K_HAT_EDOID: EdoId = EdoId::JointPublicKey(JVEPK_K_HAT_KEY_PURPOSE);

#[allow(non_upper_case_globals)]
const JVEPK_K_HAT_RID: ResourceId = ResourceId::ElectionDataObject(JVEPK_K_HAT_EDOID);

#[allow(non_upper_case_globals)]
const JVEPK_K_HAT_RIDFMT_ValidatedEdo: ResourceIdFormat = ResourceIdFormat {
    rid: JVEPK_K_HAT_RID,
    fmt: ResourceFormat::ValidElectionDataObject,
};

//=================================================================================================|

#[allow(non_snake_case)]
fn maybe_produce_JVEPK_K_KHAT_ValidatedEdo(rp_op: &Arc<RpOp>) -> Option<ResourceProductionResult> {
    Some(async_global_executor::block_on(
        produce_JVEPK_K_KHAT_ValidatedEdo(rp_op),
    ))
}

#[allow(non_snake_case)]
async fn produce_JVEPK_K_KHAT_ValidatedEdo(rp_op: &Arc<RpOp>) -> ResourceProductionResult {
    let ResourceIdFormat { rid, fmt } = rp_op.requested_ridfmt();

    let opt_guardian_key_purpose = match fmt {
        ResourceFormat::ValidElectionDataObject => {
            match *rid {
                JVEPK_K_RID => Some(JVEPK_K_KEY_PURPOSE),
                JVEPK_K_HAT_RID => Some(JVEPK_K_HAT_KEY_PURPOSE),
                /*
                ResourceId::ElectionDataObject(EdoId::JointPublicKey(guardian_key_purpose @ GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields)) => Some(guardian_key_purpose),
                ResourceId::ElectionDataObject(EdoId::JointPublicKey(guardian_key_purpose @ GuardianKeyPurpose::Encrypt_Ballot_AdditionalFreeFormData)) => Some(guardian_key_purpose),
                // */
                _ => None,
            }
        }
        _ => None,
    };

    let Some(guardian_key_purpose) = opt_guardian_key_purpose else {
        let e = ResourceProductionError::UnexpectedResourceIdFormatRequested {
            ridfmt_expected: JVEPK_K_RIDFMT_ValidatedEdo,
            ridfmt_requested: rp_op.requested_ridfmt().clone(),
        };
        Err(e)?
    };

    /*
    let rid = opt_guardian_key_purpose.map(|guardian_key_purpose| {
        ResourceId::ElectionDataObject(EdoId::JointPublicKey(purpose))
    })
    let ridfmt = ResourceIdFormat {
        rid: ResourceId::ElectionDataObject(EdoId::JointPublicKey(purpose)),
        fmt
    };

    rp_op.check_ridfmt(&JVEPK_K_RIDFMT_ValidatedEdo)?;
    // */

    let jpk = async_global_executor::block_on(JointPublicKey::compute(
        rp_op.as_ref(),
        guardian_key_purpose,
    ))?;

    let election_parameters = rp_op.election_parameters().await?;
    jpk.validate(&election_parameters)?;
    let arc: Arc<dyn Resource> = Arc::new(jpk);
    let rpsrc = ResourceSource::Valid(ValidReason::Inherent);
    Ok((arc, rpsrc))
}

//=================================================================================================|

fn gather_rpspecific_registrations(register_fn: &mut dyn FnMut(RPFnRegistration)) {
    register_fn(RPFnRegistration::new_defaultproducer(
        JVEPK_K_RIDFMT_ValidatedEdo,
        Box::new(maybe_produce_JVEPK_K_KHAT_ValidatedEdo),
    ));
    register_fn(RPFnRegistration::new_defaultproducer(
        JVEPK_K_HAT_RIDFMT_ValidatedEdo,
        Box::new(maybe_produce_JVEPK_K_KHAT_ValidatedEdo),
    ));
}

inventory::submit! {
    GatherRPFnRegistrationsFnWrapper(gather_rpspecific_registrations)
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use num_bigint::BigUint;
    use tracing::{
        debug, error, field::display as trace_display, info, info_span, instrument, trace,
        trace_span, warn,
    };

    use util::{
        algebra::{FieldElement, ScalarField},
        algebra_utils::DiscreteLog,
    };

    use super::{Ciphertext, JointPublicKey};
    use crate::{
        eg::Eg,
        errors::EgResult,
        fixed_parameters::FixedParameters,
        guardian::GuardianKeyPurpose,
        guardian_secret_key::SecretCoefficient,
        resource::{ProduceResource, ProduceResourceExt},
    };

    fn decrypt_ciphertext(
        ciphertext: &Ciphertext,
        joint_key: &JointPublicKey,
        s: &SecretCoefficient,
        fixed_parameters: &FixedParameters,
    ) -> FieldElement {
        let group = fixed_parameters.group();
        let s = &s.0;
        let alpha_s = ciphertext.alpha.exp(s, group);
        let alpha_s_inv = alpha_s.inv(group).unwrap();
        let group_msg = ciphertext.beta.mul(&alpha_s_inv, group);
        let base = &joint_key.group_element;
        let dlog = DiscreteLog::from_group(base, group);
        dlog.ff_find(&group_msg, fixed_parameters.field()).unwrap() // plaintext
    }

    #[test_log::test]
    #[ignore]
    pub fn jvepk_k_scaling() {
        async_global_executor::block_on(async {
            use crate::guardian::GuardianKeyPurpose;
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "eg::joint_public_key::t::jvepk_k_scaling",
            );

            let election_parameters = eg.election_parameters().await.unwrap();
            let election_parameters = election_parameters.as_ref();

            let fixed_parameters = election_parameters.fixed_parameters();

            let field = election_parameters.fixed_parameters().field();

            let guardian_key_purpose =
                GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields;

            let sk = eg
                .guardians_secret_keys(guardian_key_purpose)
                .await
                .unwrap()
                .iter()
                .fold(ScalarField::zero(), |a, b| {
                    a.add(&b.secret_coefficients().0[0].0, field)
                });
            let secret_coeff = SecretCoefficient(sk);

            let joint_public_key = eg.joint_public_key(guardian_key_purpose).await.unwrap();

            debug!("key_purpose: {guardian_key_purpose}");
            debug!("joint_public_key {joint_public_key:?}");

            let nonce = FieldElement::from(BigUint::from(5u8), field);
            debug!("nonce {nonce:?}");

            let ciphertext = joint_public_key.encrypt_to(fixed_parameters, &nonce, 1_u32);
            debug!("ciphertext {ciphertext:?}");

            let factor = FieldElement::from(BigUint::new(vec![0, 64u32]), field); // 2^38
            debug!("factor: {factor:?}");
            let factor = factor.sub(&ScalarField::one(), field); // 2^38 - 1
            debug!("factor: {factor:?}");

            let scaled_ciphertext = ciphertext.scale(fixed_parameters, &factor);
            debug!("scaled_ciphertext: {scaled_ciphertext:?}");

            let ciphertext = scaled_ciphertext;

            let result = decrypt_ciphertext(
                &ciphertext,
                &joint_public_key,
                &secret_coeff,
                fixed_parameters,
            );
            debug!("decrypted result: {result:?}");

            assert_eq!(result, factor);
        });
    }

    /* //? TODO
    #[test_log::test]
    pub fn jbdepk_khat() {
        async_global_executor::block_on(jbdepk_khat_async());
    }

    async fn jbdepk_khat_async() {
        use crate::guardian::GuardianKeyPurpose;
        let _eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::joint_public_key::t::jbdepk_khat",
        );
    }
    // */
}
