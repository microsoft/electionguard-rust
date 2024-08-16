// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

//! This module provides the implementation of the [`JointElectionPublicKey`] and [`Ciphertext`] for ballot encryption.
//! For more details see Sections `3.2.2` and `3.3` of the Electionguard specification `2.0.0`.

use anyhow::{ensure, Context, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use util::algebra::{FieldElement, Group, GroupElement};

use crate::{
    ciphertext::Ciphertext,
    election_parameters::ElectionParameters,
    errors::{EgError, EgResult},
    fixed_parameters::FixedParameters,
    guardian_public_key::GuardianPublicKey,
    serializable::SerializablePretty,
};

/// The joint election public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JointElectionPublicKey {
    pub joint_election_public_key: GroupElement,
}

impl JointElectionPublicKey {
    pub fn compute(
        election_parameters: &ElectionParameters,
        guardian_public_keys: &[GuardianPublicKey],
    ) -> EgResult<Self> {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;
        let n = varying_parameters.n.get_one_based_usize();
        let group = &fixed_parameters.group;

        // Validate every supplied guardian public key.
        for guardian_public_key in guardian_public_keys {
            guardian_public_key.validate(election_parameters)?;
        }

        // Verify that every guardian is represented exactly once.
        let mut seen = vec![false; n];
        for guardian_public_key in guardian_public_keys {
            let seen_ix = guardian_public_key.i.get_zero_based_usize();

            if seen.get(seen_ix).cloned().unwrap_or(true) {
                return Err(EgError::JointElectionPublicKeyCompute_GuardianMultiple(
                    guardian_public_key.i,
                ));
            }

            seen[seen_ix] = true;
        }

        let missing_guardian_ixs: Vec<usize> = seen
            .iter()
            .enumerate()
            .filter(|&(_ix, &seen)| !seen)
            .map(|(ix, _)| ix)
            .collect();

        if !missing_guardian_ixs.is_empty() {
            //? TODO Consider using `.intersperse(", ")` when it's stable.
            // https://github.com/rust-lang/rust/issues/79524
            let iter = missing_guardian_ixs.iter().enumerate().map(|(n, ix)| {
                let guardian_i = ix + 1;
                if 0 == n {
                    format!("{guardian_i}")
                } else {
                    format!(", {guardian_i}")
                }
            });

            let s = iter.collect::<String>();
            return Err(EgError::JointElectionPublicKeyCompute_GuardiansMissing(s));
        }

        let joint_election_public_key = guardian_public_keys.iter().fold(
            Group::one(),
            |acc, guardian_public_key| -> GroupElement {
                acc.mul(guardian_public_key.public_key_k_i_0(), group)
            },
        );

        Ok(Self {
            joint_election_public_key,
        })
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
        let field = &fixed_parameters.field;
        let group = &fixed_parameters.group;

        let alpha = group.g_exp(nonce);
        let exponent = &nonce.add(&FieldElement::from(value, field), field);
        let beta = self.joint_election_public_key.exp(exponent, group);

        Ciphertext { alpha, beta }
    }

    /// Reads a `JointElectionPublicKey` from a `std::io::Read` and validates it.
    pub fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        election_parameters: &ElectionParameters,
    ) -> Result<Self> {
        let self_: Self =
            serde_json::from_reader(stdioread).context("Reading JointElectionPublicKey")?;

        self_.validate(election_parameters)?;

        Ok(self_)
    }

    /// Verifies that the `JointElectionPublicKey` conforms to the election parameters.
    /// Useful after deserialization.
    pub fn validate(&self, election_parameters: &ElectionParameters) -> Result<()> {
        let group = &election_parameters.fixed_parameters.group;
        ensure!(self.joint_election_public_key.is_valid(group));
        ensure!(self.joint_election_public_key != Group::one());
        Ok(())
    }

    /// Returns the `JointElectionPublicKey` as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_left_pad(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        self.joint_election_public_key
            .to_be_bytes_left_pad(&fixed_parameters.group)
    }
}

impl SerializablePretty for JointElectionPublicKey {}

impl AsRef<GroupElement> for JointElectionPublicKey {
    #[inline]
    fn as_ref(&self) -> &GroupElement {
        &self.joint_election_public_key
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use num_bigint::BigUint;
    use util::{
        algebra::{FieldElement, ScalarField},
        algebra_utils::DiscreteLog,
        csprng::Csprng,
    };

    use crate::{
        example_election_parameters::example_election_parameters,
        fixed_parameters::FixedParameters,
        guardian_secret_key::{GuardianSecretKey, SecretCoefficient},
        index::Index,
    };

    use super::{Ciphertext, JointElectionPublicKey};

    fn g_key(i: u32) -> GuardianSecretKey {
        let mut seed = Vec::new();
        let customization_data = format!("GuardianSecretKeyGenerate({})", i.clone());
        seed.extend_from_slice(&(customization_data.as_bytes().len() as u64).to_be_bytes());
        seed.extend_from_slice(customization_data.as_bytes());

        let mut csprng = Csprng::new(&seed);

        GuardianSecretKey::generate(
            &mut csprng,
            &example_election_parameters(),
            Index::from_one_based_index_const(i).unwrap(),
            None,
        )
    }

    fn decrypt_ciphertext(
        ciphertext: &Ciphertext,
        joint_key: &JointElectionPublicKey,
        s: &SecretCoefficient,
        fixed_parameters: &FixedParameters,
    ) -> FieldElement {
        let group = &fixed_parameters.group;
        let s = &s.0;
        let alpha_s = ciphertext.alpha.exp(s, group);
        let alpha_s_inv = alpha_s.inv(group).unwrap();
        let group_msg = ciphertext.beta.mul(&alpha_s_inv, group);
        let base = &joint_key.joint_election_public_key;
        let dlog = DiscreteLog::from_group(base, group);
        dlog.ff_find(&group_msg, &fixed_parameters.field).unwrap() // plaintext
    }

    #[test]
    pub fn test_scaling_ciphertext() {
        let election_parameters = example_election_parameters();
        let field = &election_parameters.fixed_parameters.field;

        let sks: Vec<_> = (1..6).map(g_key).collect();
        let guardian_public_keys: Vec<_> = sks.iter().map(|sk| sk.make_public_key()).collect();

        let sk = sks.iter().fold(ScalarField::zero(), |a, b| {
            a.add(&b.secret_coefficients.0[0].0, field)
        });
        let s = SecretCoefficient(sk);

        let joint_election_public_key =
            JointElectionPublicKey::compute(&election_parameters, guardian_public_keys.as_slice())
                .unwrap();

        let nonce = FieldElement::from(BigUint::from(5u8), field);

        let encryption = joint_election_public_key.encrypt_to(
            &election_parameters.fixed_parameters,
            &nonce,
            1_u32,
        );

        let factor = FieldElement::from(BigUint::new(vec![0, 64u32]), field); // 2^38
        let factor = factor.sub(&ScalarField::one(), field); // 2^38 - 1

        let encryption = encryption.scale(&election_parameters.fixed_parameters, &factor);

        let result = decrypt_ciphertext(
            &encryption,
            &joint_election_public_key,
            &s,
            &election_parameters.fixed_parameters,
        );

        assert_eq!(result, factor);
    }
}
