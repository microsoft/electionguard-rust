// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{bail, ensure, Context, Result};
use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};

use crate::{
    election_parameters::ElectionParameters, fixed_parameters::FixedParameters,
    guardian_public_key::GuardianPublicKey, index::Index,
};

/// The joint election public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointElectionPublicKey {
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub joint_election_public_key: BigUint,
}

/// A 1-based index of a [`Ciphertext`] in the order it is defined in the [`crate::contest_encrypted::ContestEncrypted`].
pub type CiphertextIndex = Index<Ciphertext>;

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
        let n = varying_parameters.n.get_one_based_usize();

        // Validate every supplied guardian public key.
        for guardian_public_key in guardian_public_keys {
            guardian_public_key.validate(election_parameters)?;
        }

        // Verify that every guardian is represented exactly once.
        let mut seen = vec![false; n];
        for guardian_public_key in guardian_public_keys {
            let seen_ix = guardian_public_key.i.get_zero_based_usize();

            ensure!(
                !seen[seen_ix],
                "Guardian {} is represented more than once in the guardian public keys",
                guardian_public_key.i
            );

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

            bail!("Guardian(s) {iter:?} are not represented in the guardian public keys");
        }

        let joint_election_public_key = guardian_public_keys.iter().fold(
            BigUint::one(),
            |mut acc, guardian_public_key| -> BigUint {
                acc *= guardian_public_key.public_key_k_i_0();
                acc % fixed_parameters.p.as_ref()
            },
        );

        Ok(Self {
            joint_election_public_key,
        })
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
            .modpow(nonce, fixed_parameters.p.as_ref());
        let beta = self
            .joint_election_public_key
            .modpow(&(nonce + vote), fixed_parameters.p.as_ref());

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
        ensure!(
            election_parameters
                .fixed_parameters
                .is_valid_modp(&self.joint_election_public_key),
            "JointElectionPublicKey is not valid mod p"
        );
        Ok(())
    }

    /// Returns the `JointElectionPublicKey` as a big-endian byte array of the correct length for `mod p`.
    pub fn to_be_bytes_len_p(&self, fixed_parameters: &FixedParameters) -> Vec<u8> {
        fixed_parameters.biguint_to_be_bytes_len_p(&self.joint_election_public_key)
    }

    /// Writes a `JointElectionPublicKey` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing JointElectionPublicKey")
    }
}

impl AsRef<BigUint> for JointElectionPublicKey {
    #[inline]
    fn as_ref(&self) -> &BigUint {
        &self.joint_election_public_key
    }
}
