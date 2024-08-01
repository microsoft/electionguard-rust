// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides implementation of guardian secret keys. For more details see Section `3.2` of the Electionguard specification `2.0.0`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use util::{
    algebra::{FieldElement, GroupElement},
    csprng::Csprng,
};

use crate::{
    election_parameters::ElectionParameters,
    fixed_parameters::FixedParameters,
    guardian::GuardianIndex,
    guardian_coeff_proof::CoefficientProof,
    guardian_public_key::GuardianPublicKey,
    guardian_public_key_info::{
        validate_guardian_public_key_info, GuardianPublicKeyInfo, PublicKeyValidationError,
    },
    serializable::SerializablePretty,
};

/// A polynomial coefficient used to define a secret key sharing.
///
/// This corresponds to the `a_{i,j}` in Equation `9`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretCoefficient(pub FieldElement);

/// A vector of [`SecretCoefficient`]s defining a sharing of the guardian's secret key.
///
/// "Each guardian G_i in an election with a decryption threshold of k generates k secret
/// polynomial coefficients a_i,j, for 0 ≤ j < k, by sampling them uniformly, at random in
/// the range 0 ≤ a_i,j < q.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretCoefficients(pub Vec<SecretCoefficient>);

impl SecretCoefficients {
    /// This function generates a fresh [`SecretCoefficients`].
    ///
    /// The arguments are
    /// - `csprng` - secure randomness generator
    /// - `election_parameters` - the election parameters
    pub fn generate(csprng: &mut Csprng, election_parameters: &ElectionParameters) -> Self {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;

        let field = &fixed_parameters.field;
        let k = varying_parameters.k;

        SecretCoefficients(
            (0..k.get_one_based_u32())
                .map(|_j| SecretCoefficient(field.random_field_elem(csprng)))
                .collect(),
        )
    }
}

/// A commitment to a single [`SecretCoefficient`].
///
/// This corresponds to the `K_{i,j}` in Equation `10`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoefficientCommitment(pub GroupElement);

impl CoefficientCommitment {
    /// Returns the [`CoefficientCommitment`] as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_left_pad(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        self.0.to_be_bytes_left_pad(&fixed_parameters.group)
    }
}

/// A vector of [`CoefficientCommitment`]s, defining the guardians public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoefficientCommitments(pub Vec<CoefficientCommitment>);

impl CoefficientCommitments {
    /// This function computes the [`CoefficientCommitments`] for given [`SecretCoefficients`].
    ///
    /// The arguments are
    /// - `fixed_parameters` - the fixed parameters    
    /// - `secret_coefficients` - the secret coefficients
    pub fn new(
        fixed_parameters: &FixedParameters,
        secret_coefficients: &SecretCoefficients,
    ) -> Self {
        CoefficientCommitments(
            secret_coefficients
                .0
                .iter()
                .map(|secret_coefficient| {
                    CoefficientCommitment(fixed_parameters.group.g_exp(&secret_coefficient.0))
                })
                .collect(),
        )
    }
}

/// The secret key for a guardian.
///
/// See Section `3.2.2` for details on the generation of secret keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianSecretKey {
    /// Guardian index, 1 <= i <= [`n`](crate::varying_parameters::VaryingParameters::n).
    pub i: GuardianIndex,

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub opt_name: Option<String>,

    /// Secret polynomial coefficients.
    pub secret_coefficients: SecretCoefficients,

    /// "Published" polynomial coefficient commitments.
    pub coefficient_commitments: CoefficientCommitments,

    /// Proofs of knowledge for secret coefficients.
    pub coefficient_proofs: Vec<CoefficientProof>,
}

impl GuardianPublicKeyInfo for GuardianSecretKey {
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

impl GuardianSecretKey {
    /// This function generates a fresh [`GuardianSecretKey`] for guardian `i`.
    ///
    /// The arguments are
    /// - `csprng` - secure randomness generator
    /// - `election_parameters` - the election parameters
    /// - `i` - the guardian's index
    /// - `opt_name` - an optional name
    pub fn generate(
        csprng: &mut Csprng,
        election_parameters: &ElectionParameters,
        i: GuardianIndex,
        opt_name: Option<String>,
    ) -> Self {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let secret_coefficients = SecretCoefficients::generate(csprng, election_parameters);

        let coefficient_commitments =
            CoefficientCommitments::new(fixed_parameters, &secret_coefficients);

        let coefficient_proofs = secret_coefficients
            .0
            .iter()
            .zip(&coefficient_commitments.0)
            .enumerate()
            .map(|(j, (coef, com))| {
                CoefficientProof::new(
                    csprng,
                    fixed_parameters,
                    i.get_one_based_u32(),
                    j as u32,
                    coef,
                    com,
                )
            })
            .collect();

        GuardianSecretKey {
            secret_coefficients,
            coefficient_commitments,
            coefficient_proofs,
            i,
            opt_name,
        }
    }

    /// This function verifies that the `GuardianSecretKey` is well-formed and conforms to the election parameters.
    /// Useful after deserialization.
    pub fn validate(
        &self,
        election_parameters: &ElectionParameters,
    ) -> Result<(), PublicKeyValidationError> {
        validate_guardian_public_key_info(self, election_parameters)
    }

    /// This function returns the [`SecretCoefficients`] of the [`GuardianSecretKey`].
    pub fn secret_coefficients(&self) -> &SecretCoefficients {
        &self.secret_coefficients
    }

    /// This function returns the actual secret key of the [`GuardianSecretKey`].
    ///
    /// The returned value corresponds to `a_{i,0}` as defined in Section `3.2.2`.
    pub fn secret_s(&self) -> &FieldElement {
        &self.secret_coefficients.0[0].0
    }

    /// This function computes the [`GuardianPublicKey`] corresponding to the [`GuardianSecretKey`].
    pub fn make_public_key(&self) -> GuardianPublicKey {
        GuardianPublicKey {
            i: self.i,
            opt_name: self.opt_name.clone(),
            coefficient_commitments: self.coefficient_commitments.clone(),
            coefficient_proofs: self.coefficient_proofs.clone(),
        }
    }

    /// Reads a [`GuardianSecretKey`] from a [`std::io::Read`] and validates it.
    pub fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        election_parameters: &ElectionParameters,
    ) -> Result<Self> {
        let self_: Self =
            serde_json::from_reader(stdioread).context("Reading GuardianSecretKey")?;

        self_.validate(election_parameters)?;

        Ok(self_)
    }

}

impl SerializablePretty for GuardianSecretKey {}
