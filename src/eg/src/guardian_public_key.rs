// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides implementation of guardian public keys. For more details see Section `3.2` of the Electionguard specification `2.0.0`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use util::algebra::GroupElement;

use crate::{
    election_parameters::ElectionParameters,
    fixed_parameters::FixedParameters,
    guardian::GuardianIndex,
    guardian_coeff_proof::CoefficientProof,
    guardian_public_key_info::{
        validate_guardian_public_key_info, GuardianPublicKeyInfo, PublicKeyValidationError,
    },
    guardian_secret_key::CoefficientCommitments,
};

/// The public key for a guardian.
///
/// See Section `3.2.2` for details on the generation of public keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianPublicKey {
    /// Guardian index, 1 <= i <= [`n`](crate::varying_parameters::VaryingParameters::n).
    pub i: GuardianIndex,

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub opt_name: Option<String>,

    /// "Published" polynomial coefficient commitments.
    pub coefficient_commitments: CoefficientCommitments,

    /// Proofs of knowledge for secret coefficients.
    pub coefficient_proofs: Vec<CoefficientProof>,
}

impl GuardianPublicKeyInfo for GuardianPublicKey {
    fn i(&self) -> GuardianIndex {
        self.i
    }

    fn opt_name(&self) -> &Option<String> {
        &self.opt_name
    }

    fn coefficient_commitments(&self) -> &CoefficientCommitments {
        &self.coefficient_commitments
    }

    fn coefficient_proofs(&self) -> &[CoefficientProof] {
        &self.coefficient_proofs
    }
}

impl GuardianPublicKey {
    /// This function verifies that the [`GuardianPublicKey`] is well-formed
    /// and conforms to the election parameters.
    /// Useful after deserialization.
    pub fn validate(
        &self,
        election_parameters: &ElectionParameters,
    ) -> Result<(), PublicKeyValidationError> {
        validate_guardian_public_key_info(self, election_parameters)
    }

    /// This function returns the actual public key of the [`GuardianPublicKey`].
    ///
    /// The return value corresponds to commitment `K_i,0` in Section `3.2.2`.
    pub fn public_key_k_i_0(&self) -> &GroupElement {
        &self.coefficient_commitments.0[0].0
    }

    /// This function returns the actual public key as a big-endian byte vector
    /// of length [`l_p`](util::algebra::Group::l_p).
    pub fn to_be_bytes_left_pad(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        self.public_key_k_i_0()
            .to_be_bytes_left_pad(&fixed_parameters.group)
    }

    /// Writes a [`GuardianPublicKey`] to a [`std::io::Write`].
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing GuardianPublicKey")
    }

    /// Reads a [`GuardianPublicKey`] from a [`std::io::Read`] and validates it.
    pub fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        election_parameters: &ElectionParameters,
    ) -> Result<Self> {
        let self_: Self =
            serde_json::from_reader(stdioread).context("Reading GuardianPublicKey")?;

        self_.validate(election_parameters)?;

        Ok(self_)
    }

    /// Returns a pretty JSON `String` representation of the [`GuardianPublicKey`].
    /// The final line will end with a newline.
    pub fn to_json(&self) -> String {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    //use super::*;
    use crate::{
        example_election_parameters::example_election_parameters,
        guardian_secret_key::GuardianSecretKey,
    };
    use util::csprng::Csprng;

    #[test]
    fn test_key_generation() {
        let mut csprng = Csprng::new(b"test_key_generation");

        let election_parameters = example_election_parameters();
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;

        let k = varying_parameters.k.as_quantity();

        let guardian_secret_keys = varying_parameters
            .each_guardian_i()
            .map(|i| GuardianSecretKey::generate(&mut csprng, &election_parameters, i, None))
            .collect::<Vec<_>>();

        let guardian_public_keys = guardian_secret_keys
            .iter()
            .map(|secret_key| secret_key.make_public_key())
            .collect::<Vec<_>>();

        for guardian_secret_key in guardian_secret_keys.iter() {
            assert_eq!(guardian_secret_key.secret_coefficients.0.len(), k);
            assert_eq!(guardian_secret_key.coefficient_commitments.0.len(), k);

            for secret_coefficient in guardian_secret_key.secret_coefficients.0.iter() {
                assert!(&secret_coefficient.0.is_valid(&fixed_parameters.field));
            }

            for coefficient_commitment in guardian_secret_key.coefficient_commitments.0.iter() {
                assert!(&coefficient_commitment.0.is_valid(&fixed_parameters.group));
            }
        }

        for (i, guardian_public_key) in guardian_public_keys.iter().enumerate() {
            assert_eq!(guardian_public_key.coefficient_commitments.0.len(), k);

            for (j, coefficient_commitment) in guardian_public_key
                .coefficient_commitments
                .0
                .iter()
                .enumerate()
            {
                assert_eq!(
                    &coefficient_commitment.0,
                    &guardian_secret_keys[i].coefficient_commitments.0[j].0
                );
            }

            assert_eq!(
                guardian_public_key.public_key_k_i_0(),
                &guardian_public_key.coefficient_commitments.0[0].0
            );
        }
    }
}
