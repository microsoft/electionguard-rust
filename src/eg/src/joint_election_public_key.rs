// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{bail, Context, Result};
use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};

use crate::{
    election_parameters::ElectionParameters, fixed_parameters::FixedParameters,
    guardian_public_key::GuardianPublicKey,
};

/// The joint election public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointElectionPublicKey(
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub BigUint,
);

impl JointElectionPublicKey {
    pub fn compute(
        election_parameters: &ElectionParameters,
        guardian_public_keys: &[GuardianPublicKey],
    ) -> Result<Self> {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;
        let n: usize = varying_parameters.n.into();

        // Validate every supplied guardian public key.
        for guardian_public_key in guardian_public_keys {
            guardian_public_key.validate(election_parameters)?;
        }

        // Verify that every guardian is represented exactly once.
        let mut seen = vec![false; n];
        for guardian_public_key in guardian_public_keys {
            // Convert from 1-based indexing to 0-based.
            let seen_ix = guardian_public_key.i.get() as usize - 1;

            if seen[seen_ix] {
                bail!(
                    "Guardian {} is represented more than once in the guardian public keys",
                    guardian_public_key.i
                );
            }

            seen[seen_ix] = true;
        }

        let missing_ix: Vec<usize> = seen
            .iter()
            .enumerate()
            .filter(|&(_ix, &seen)| !seen)
            .map(|(ix, _)| ix)
            .collect();

        if !missing_ix.is_empty() {
            //? TODO Consider using `.intersperse(", ")` when it's stable.
            // https://github.com/rust-lang/rust/issues/79524
            let iter = missing_ix.iter().enumerate().map(|(n, ix)| {
                if 0 == n {
                    format!("{}", ix + 1)
                } else {
                    format!(", {}", ix + 1)
                }
            });

            bail!("Guardian(s) {iter:?} are not represented in the guardian public keys");
        }

        Ok(Self(guardian_public_keys.iter().fold(
            BigUint::one(),
            |acc, public_key| {
                let k0 = public_key.public_key_k0();
                acc.modpow(k0, fixed_parameters.p.as_ref())
            },
        )))
    }

    /// Returns the `JointElectionPublicKey` as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_len_p(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        fixed_parameters.biguint_to_be_bytes_len_p(&self.0)
    }

    //? TODO from_stdioread_validated

    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .context("Error writing joint election public key")?;

        ser.into_inner()
            .write_all(b"\n")
            .context("Error writing joint election public key file")
    }
}
