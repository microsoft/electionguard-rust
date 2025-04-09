// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides the implementation of the [`JointPublicKey`] and [`Ciphertext`] for ballot encryption.
//! For more details see Sections `3.2.2` and `3.3` of the Electionguard specification `2.0.0`. [TODO fix ref]

use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use util::{
    algebra::{FieldElement, Group, GroupElement},
    index::IndexResult,
};

use crate::{
    ciphertext::Ciphertext,
    eg::Eg,
    election_parameters::ElectionParameters,
    errors::{EgError, EgResult},
    fixed_parameters::FixedParameters,
    guardian::{GuardianIndex, GuardianKeyPurpose},
    guardian_public_key_trait::GuardianKeyInfoTrait,
    resource::{ElectionDataObjectId, Resource, ResourceId, ResourceIdFormat},
    serializable::SerializableCanonical,
};

/// The joint election public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JointPublicKey {
    /// The [`GroupElement`].
    pub(crate) group_element: GroupElement,

    /// Refers to this object as a [`Resource`].
    /// Also, encodes the [`GuardianKeyPurpose`].
    #[serde(skip_serializing)]
    ridfmt: ResourceIdFormat,
}

impl JointPublicKey {
    /// [Key purpose](crate::guardian::GuardianKeyPurpose)
    pub fn key_purpose(&self) -> EgResult<GuardianKeyPurpose> {
        use ElectionDataObjectId::JointPublicKey;
        use ResourceId::ElectionDataObject;
        let ElectionDataObject(JointPublicKey(key_purpose)) = self.ridfmt.rid else {
            return Err(EgError::UnexpectedResourceIdFormat {
                ridfmt: self.ridfmt.clone(),
                ty: "JointPublicKey",
            });
        };
        Ok(key_purpose)
    }

    /// The [`GroupElement`] used in asymmetric encryption operations.
    pub fn group_element(&self) -> &GroupElement {
        &self.group_element
    }

    /// Computes the [`JointPublicKey`].
    pub fn compute(produce_resource: &(dyn ProduceResource + Send + Sync + 'static), key_purpose: GuardianKeyPurpose) -> EgResult<JointPublicKey> {
        let election_parameters = produce_resource.election_parameters().await?;
        let election_parameters = election_parameters.as_ref();
        let fixed_parameters = election_parameters.fixed_parameters();
        let group = fixed_parameters.group();

        let varying_parameters = election_parameters.varying_parameters();
        let n = varying_parameters.n().get_one_based_usize();

        let gpks = produce_resource.guardian_public_keys(key_purpose)?;
        let gpks = gpks.map_into(Arc::as_ref);

        // Validate every guardian public key against the election parameters.
        for &gpk in gpks.iter() {
            gpk.validate_public_key_info_to_election_parameters(eg)?;
        }

        // Validate that every guardian is represented exactly once.
        let mut seen = vec![false; n];
        for &gpk in gpks.iter() {
            let seen_ix0 = gpk.i().get_zero_based_usize();

            if seen.get(seen_ix0).cloned().unwrap_or(true) {
                return Err(EgError::JointPublicKeyCompute_GuardianMultiple(
                    gpk.i(),
                ));
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

        let jpk_group_elem = guardian_pub_keys_k_i_0
            .iter()
            .fold(Group::one(), |acc, &gpk_k_i_0| -> GroupElement {
                acc.mul(gpk_k_i_0, group)
            });

        let ridfmt = ElectionDataObjectId::JointPublicKey(key_purpose).validated_type_ridfmt();

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
    pub fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        election_parameters: &ElectionParameters,
    ) -> Result<Self> {
        let self_: Self =
            serde_json::from_reader(stdioread).context("Reading JointPublicKey")?;

        self_.validate(election_parameters)?;

        Ok(self_)
    }

    /// Validates that the `JointPublicKey` conforms to the election parameters.
    pub fn validate(&self, election_parameters: &ElectionParameters) -> EgResult<()> {
        let key_purpose = self.key_purpose()?;
        let group = election_parameters.fixed_parameters().group();
        let valid = self.group_element.is_valid(group) && self.group_element != Group::one();
        if !valid {
            return Err(EgError::JointPublicKey_InvalidGroupElement(
                key_purpose,
            ));
        }
        Ok(())
    }

    /// Returns the `JointPublicKey` as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_left_pad(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        self.group_element
            .to_be_bytes_left_pad(group)
    }
}

impl AsRef<JointPublicKey> for JointPublicKey {
    #[inline]
    fn as_ref(&self) -> &JointPublicKey {
        self
    }
}

impl AsRef<GroupElement> for JointPublicKey {
    #[inline]
    fn as_ref(&self) -> &GroupElement {
        &self.group_element
    }
}

impl SerializableCanonical for JointPublicKey {}

crate::impl_knows_friendly_type_name! { JointPublicKey }

impl Resource for JointPublicKey {
    // Unwrap() is justified here because that expression is evaluated in the debug build only.
    #[allow(clippy::unwrap_used)]
    fn ridfmt(&self) -> &ResourceIdFormat {
        debug_assert_eq!(
            self.ridfmt,
            ElectionDataObjectId::JointPublicKey(self.key_purpose().unwrap())
                .validated_type_ridfmt()
        );
        &self.ridfmt
    }
}

//=================================================================================================|

#[cfg(test)]
#[cfg(any(not(debug_assertions), miri))]
#[allow(clippy::unwrap_used)]
mod t {
    use num_bigint::BigUint;
    use util::{
        algebra::{FieldElement, ScalarField},
        algebra_utils::DiscreteLog,
    };

    use crate::{
        eg::Eg, errors::EgResult, fixed_parameters::FixedParameters,
        guardian_secret_key::SecretCoefficient,
    };

    use super::{Ciphertext, JointPublicKey};

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
        dlog.ff_find(&group_msg, &fixed_parameters.field).unwrap() // plaintext
    }

    #[test_log::test]
    pub fn test_scaling_ciphertext() -> EgResult<()> {
        let mut eg = Eg::new_insecure_deterministic_with_example_election_data(
            "electionguard-rust/src/eg::joint_public_key::test::test_scaling_ciphertext",
        );
        eg.generate_example_election_data(true);
        let eg = &mut eg;

        JointPublicKey::get_or_compute(eg).unwrap();

        let election_parameters = produce_resource.election_parameters().await?.as_ref();
        let fixed_parameters = election_parameters.fixed_parameters();
        let field = election_parameters.fixed_parameters().field;

        let sk = eg
            .guardians_secret_keys()?
            .iter()
            .fold(ScalarField::zero(), |a, b| {
                a.add(&b.secret_coefficients.0[0].0, field)
            });
        let secret_coeff = SecretCoefficient(sk);

        let nonce = FieldElement::from(BigUint::from(5u8), field);

        let joint_public_key = eg.joint_public_key()?;
        let encryption = joint_public_key.encrypt_to(fixed_parameters, &nonce, 1_u32);

        let factor = FieldElement::from(BigUint::new(vec![0, 64u32]), field); // 2^38
        let factor = factor.sub(&ScalarField::one(), field); // 2^38 - 1

        let encryption = encryption.scale(fixed_parameters, &factor);

        let result = decrypt_ciphertext(
            &encryption,
            &joint_public_key,
            &secret_coeff,
            fixed_parameters,
        );

        assert_eq!(result, factor);

        Ok(())
    }
}
