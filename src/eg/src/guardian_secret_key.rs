// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;

use anyhow::{ensure, Context, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use util::csprng::Csprng;

use crate::{
    election_parameters::ElectionParameters,
    fixed_parameters::FixedParameters,
    guardian::GuardianIndex,
    guardian_public_key::GuardianPublicKey,
    guardian_public_key_info::{validate_guardian_public_key_info, GuardianPublicKeyInfo},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretCoefficient(
    //? TODO ensure this is serialized in a fixed-length format
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub BigUint,
);

impl SecretCoefficient {
    /// Returns the `SecretCoefficient` as a big-endian byte array of the correct length for `mod q`.
    pub fn to_be_bytes_len_q(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        fixed_parameters.biguint_to_be_bytes_len_q(&self.0)
    }
}

/// "Each guardian G_i in an election with a decryption threshold of k generates k secret
/// polynomial coefficients a_i,j, for 0 ≤ j < k, by sampling them uniformly, at random in
/// the range 0 ≤ a_i,j < q.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretCoefficients(pub Vec<SecretCoefficient>);

impl SecretCoefficients {
    pub fn generate(csprng: &mut Csprng, election_parameters: &ElectionParameters) -> Self {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;

        let k = varying_parameters.k;

        SecretCoefficients(
            (0..k.get_one_based_u32())
                .map(|_j| SecretCoefficient(csprng.next_biguint_lt(fixed_parameters.q.borrow())))
                .collect(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoefficientCommitment(
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub BigUint,
);

impl CoefficientCommitment {
    /// Verifies that `CoefficientCommitment` is well-formed and conforms
    /// to the election parameters. Useful after deserialization.
    pub(crate) fn validate(&self, election_parameters: &ElectionParameters) -> Result<()> {
        ensure!(
            election_parameters.fixed_parameters.is_valid_modp(&self.0),
            "Coefficient commitment is not a valid mod p value"
        );

        Ok(())
    }

    /// Returns the `CoefficientCommitment` as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_len_p(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        fixed_parameters.biguint_to_be_bytes_len_p(&self.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoefficientCommitments(pub Vec<CoefficientCommitment>);

impl CoefficientCommitments {
    pub fn new(
        fixed_parameters: &FixedParameters,
        secret_coefficients: &SecretCoefficients,
    ) -> Self {
        CoefficientCommitments(
            secret_coefficients
                .0
                .iter()
                .map(|secret_coefficient| {
                    CoefficientCommitment(
                        fixed_parameters
                            .g
                            .modpow(&secret_coefficient.0, fixed_parameters.p.as_ref()),
                    )
                })
                .collect(),
        )
    }
}

/// Secret key for a guardian.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianSecretKey {
    /// Guardian number, 1 <= i <= [`crate::varying_parameters::VaryingParameters::n`].
    pub i: GuardianIndex,

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub opt_name: Option<String>,

    /// Secret polynomial coefficients.
    pub secret_coefficients: SecretCoefficients,

    /// "Published" polynomial coefficient commitments.
    pub coefficient_commitments: CoefficientCommitments,
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
}

impl GuardianSecretKey {
    pub fn generate(
        csprng: &mut Csprng,
        election_parameters: &ElectionParameters,
        i: GuardianIndex,
        opt_name: Option<String>,
    ) -> Self {
        let secret_coefficients = SecretCoefficients::generate(csprng, election_parameters);
        assert_ne!(secret_coefficients.0.len(), 0);

        let coefficient_commitments = CoefficientCommitments::new(
            &election_parameters.fixed_parameters,
            &secret_coefficients,
        );
        assert_ne!(secret_coefficients.0.len(), 0);

        GuardianSecretKey {
            secret_coefficients,
            coefficient_commitments,
            i,
            opt_name,
        }
    }

    /// Reads a `GuardianSecretKey` from a `std::io::Read` and validates it.
    pub fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        election_parameters: &ElectionParameters,
    ) -> Result<Self> {
        let self_: Self =
            serde_json::from_reader(stdioread).context("Reading GuardianSecretKey")?;

        self_.validate(election_parameters)?;

        Ok(self_)
    }

    /// Verifies that the `GuardianSecretKey` is well-formed
    /// and conforms to the election parameters.
    /// Useful after deserialization.
    pub fn validate(&self, election_parameters: &ElectionParameters) -> Result<()> {
        validate_guardian_public_key_info(self, election_parameters)
    }

    pub fn secret_coefficients(&self) -> &SecretCoefficients {
        &self.secret_coefficients
    }

    pub fn secret_s(&self) -> &BigUint {
        &self.secret_coefficients.0[0].0
    }

    pub fn make_public_key(&self) -> GuardianPublicKey {
        GuardianPublicKey {
            i: self.i,
            opt_name: self.opt_name.clone(),
            coefficient_commitments: self.coefficient_commitments.clone(),
        }
    }

    /// Writes a `GuardianSecretKey` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing GuardianSecretKey")
    }
}
