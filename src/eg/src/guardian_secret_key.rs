// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;
use std::num::NonZeroU16;

use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use util::csprng::Csprng;

use crate::{
    election_parameters::ElectionParameters, fixed_parameters::FixedParameters,
    guardian_public_key::GuardianPublicKey,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretCoefficient(
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
            (0..k)
                .map(|_i| SecretCoefficient(csprng.next_biguint_lt(fixed_parameters.q.borrow())))
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
    /// Guardian number, 1 <= i <= n.
    pub i: NonZeroU16,

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    #[serde(rename = "name")]
    pub opt_name: Option<String>,

    /// Secret polynomial coefficients.
    pub secret_coefficients: SecretCoefficients,

    /// "Published" polynomial coefficient commitments.
    pub coefficient_commitments: CoefficientCommitments,
}

impl GuardianSecretKey {
    pub fn generate(
        csprng: &mut Csprng,
        election_parameters: &ElectionParameters,
        i: NonZeroU16,
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

    pub fn secret_coefficients(&self) -> &SecretCoefficients {
        &self.secret_coefficients
    }

    pub fn secret_s(&self) -> &BigUint {
        &self.secret_coefficients.0[0].0
    }

    pub fn coefficient_commitments(&self) -> &CoefficientCommitments {
        &self.coefficient_commitments
    }

    pub fn make_public_key(&self) -> GuardianPublicKey {
        GuardianPublicKey {
            i: self.i,
            opt_name: self.opt_name.clone(),
            coefficient_commitments: self.coefficient_commitments.clone(),
        }
    }

    /// Returns a pretty JSON `String` representation of the `GuardianSecretKey`.
    /// The final line will end with a newline.
    pub fn to_json(&self) -> String {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }

    /// Reads an `GuardianSecretKey` from a `std::io::Read`.
    pub fn from_reader(io_read: &mut dyn std::io::Read) -> Result<GuardianSecretKey> {
        serde_json::from_reader(io_read)
            .map_err(|e| anyhow!("Error parsing GuardianSecretKey: {}", e))
    }
}
