// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{anyhow, bail, Context, Result};
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

/// The ciphertext used to store a vote value corresponding to one option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub alpha: BigUint,
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub beta: BigUint,
    #[serde(skip)]
    pub nonce: Option<BigUint>,
}

/// Does not match nonces if either nonce is None.
impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        if self.nonce.is_some() && other.nonce.is_some() {
            return self.alpha == other.alpha
                && self.beta == other.beta
                && self.nonce == other.nonce;
        }
        self.alpha == other.alpha && self.beta == other.beta
    }
}

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

        Ok(Self(
            guardian_public_keys
                .iter()
                .fold(BigUint::one(), |acc, public_key| {
                    acc * public_key.public_key_k0() % fixed_parameters.p.as_ref()
                }),
        ))
    }

    pub fn encrypt_with(
        &self,
        fixed_parameters: &FixedParameters,
        nonce: &BigUint,
        vote: usize,
        store_nonce: bool,
    ) -> Ciphertext {
        let alpha = fixed_parameters
            .g
            .modpow(&nonce, fixed_parameters.p.as_ref());
        let beta = self.0.modpow(&(nonce + vote), fixed_parameters.p.as_ref());

        if store_nonce {
            Ciphertext {
                alpha,
                beta,
                nonce: Some(nonce.clone()),
            }
        } else {
            Ciphertext {
                alpha,
                beta,
                nonce: None,
            }
        }
    }

    /// Returns the `JointElectionPublicKey` as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_len_p(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        fixed_parameters.biguint_to_be_bytes_len_p(&self.0)
    }

    /// Returns a pretty JSON `String` representation of the `JointElectionPublicKey`.
    /// The final line will end with a newline.
    pub fn to_json(&self) -> String {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }

    /// Reads an `JointElectionPublicKey` from a `std::io::Read`.
    pub fn from_reader(io_read: &mut dyn std::io::Read) -> Result<JointElectionPublicKey> {
        serde_json::from_reader(io_read)
            .map_err(|e| anyhow!("Error parsing JointElectionPublicKey: {}", e))
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
