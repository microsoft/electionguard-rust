// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;
use std::num::NonZeroU16;

use anyhow::{Context, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use util::integer_util::to_be_bytes_left_pad;

use crate::{
    election_parameters::ElectionParameters,
    fixed_parameters::FixedParameters,
    guardian_public_key_info::{validate_guardian_public_key_info, GuardianPublicKeyInfo},
    guardian_secret_key::CoefficientCommitments,
};

/// Public key for a guardian.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianPublicKey {
    /// Guardian number, 1 <= i <= n.
    pub i: NonZeroU16,

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    #[serde(rename = "name")]
    pub opt_name: Option<String>,

    /// "Published" polynomial coefficient commitments.
    pub coefficient_commitments: CoefficientCommitments,
}

impl GuardianPublicKeyInfo for GuardianPublicKey {
    fn i(&self) -> NonZeroU16 {
        self.i
    }
    fn opt_name(&self) -> &Option<String> {
        &self.opt_name
    }
    fn coefficient_commitments(&self) -> &CoefficientCommitments {
        &self.coefficient_commitments
    }
}

impl GuardianPublicKey {
    /// Reads a `GuardianPublicKey` from a `std::io::Read` and validates it.
    pub fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        election_parameters: &ElectionParameters,
    ) -> Result<Self> {
        let self_: Self =
            serde_json::from_reader(stdioread).context("Reading GuardianPublicKey")?;

        self_.validate(election_parameters)?;

        Ok(self_)
    }

    /// Verifies that the `GuardianPublicKey` is well-formed
    /// and conforms to the election parameters.
    /// Useful after deserialization.
    pub fn validate(&self, election_parameters: &ElectionParameters) -> Result<()> {
        validate_guardian_public_key_info(self, election_parameters)
    }

    /// "commitment K_i,0 will serve as the public key for guardian G_i"
    pub fn public_key_k0(&self) -> &BigUint {
        self.coefficient_commitments.0[0].0.borrow()
    }

    /// Returns the public key `K_i,0` as a big-endian byte vector of length l_p_bytes.
    pub fn to_be_bytes_len_p(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        //? TODO: Sure would be nice if we could avoid this allocation, but since we
        // store a BigUint representation, its length in bytes may be less than `l_p_bytes`.
        to_be_bytes_left_pad(&self.public_key_k0(), fixed_parameters.l_p_bytes())
    }

    /// Returns a pretty JSON `String` representation of the `SecretKey`.
    /// The final line will end with a newline.
    pub fn to_json(&self) -> String {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }

    /// Writes a `GuardianPublicKey` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing GuardianPublicKey")
    }
}

#[cfg(test)]
mod test {
    use super::*;
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

        let k: usize = varying_parameters.k.into();

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
                assert!(&secret_coefficient.0 < fixed_parameters.q.borrow());
            }

            for coefficient_commitment in guardian_secret_key.coefficient_commitments.0.iter() {
                assert!(&coefficient_commitment.0 < fixed_parameters.p.borrow());
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
                guardian_public_key.public_key_k0(),
                &guardian_public_key.coefficient_commitments.0[0].0
            );
        }
    }
}
