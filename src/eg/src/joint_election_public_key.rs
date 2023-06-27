// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};

use crate::{fixed_parameters::FixedParameters, guardian_public_key::GuardianPublicKey};

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
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
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
    pub nonce: Option<BigUint>,
}

// /// Serialize for Ciphertext
// impl Serialize for Ciphertext {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::ser::Serializer,
//     {
//         (self.alpha.to_str_radix(16), self.beta.to_str_radix(16)).serialize(serializer)
//     }
// }

// impl<'de> Deserialize<'de> for Ciphertext {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         match <(String, String)>::deserialize(deserializer) {
//             Ok((alpha, beta)) => Ok(Ciphertext {
//                 alpha: BigUint::from_str_radix(&alpha, 16).unwrap(),
//                 beta: BigUint::from_str_radix(&beta, 16).unwrap(),
//             }),
//             Err(e) => Err(e),
//         }
//     }
// }

impl JointElectionPublicKey {
    pub fn compute(
        fixed_parameters: &FixedParameters,
        guardian_public_keys: &[GuardianPublicKey],
    ) -> Self {
        //? TODO: Would it be useful to parallelize this?
        Self(
            guardian_public_keys
                .iter()
                .fold(BigUint::one(), |acc, public_key| {
                    let k0 = public_key.public_key_k0();
                    (acc * k0) % fixed_parameters.p.as_ref()
                }),
        )
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
}
