// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    election_parameters::ElectionParameters,
    hash::{eg_h, HValue},
    hashes::Hashes,
    joint_election_public_key::JointElectionPublicKey,
    serialize::SerializablePretty,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashesExt {
    /// Extended base hash.
    pub h_e: HValue,
}

impl HashesExt {
    /// This function computes the extended base hash
    pub fn compute(
        election_parameters: &ElectionParameters,
        hashes: &Hashes,
        joint_election_public_key: &JointElectionPublicKey,
    ) -> Self {
        let fixed_parameters = &election_parameters.fixed_parameters;
        // Computation of the extended base hash H_E.
        let h_e = {
            // B1 = 12 | b(K, 512)
            let mut v = vec![0x12];
            // K = election public key
            v.append(&mut joint_election_public_key.to_be_bytes_left_pad(fixed_parameters));
            eg_h(&hashes.h_b, &v)
        };
        Self { h_e }
    }

    /// Reads a `HashesExt` from a `std::io::Read` and validates it.
    pub fn from_stdioread_validated(stdioread: &mut dyn std::io::Read) -> Result<Self> {
        let self_: Self = serde_json::from_reader(stdioread).context("Reading HashesExt")?;

        self_.validate()?;

        Ok(self_)
    }

    /// Validates that the `HashesExt` is well-formed.
    /// Useful after deserialization.
    pub fn validate(&self) -> Result<()> {
        // We currently have no validation rules for this type.
        Ok(())
    }

    /// Reads `HashesExt` from a `std::io::Read`.
    pub fn from_reader(io_read: &mut dyn std::io::Read) -> Result<HashesExt> {
        serde_json::from_reader(io_read)
            .map_err(|e| anyhow!("Error parsing JointElectionPublicKey: {}", e))
    }
}

impl SerializablePretty for HashesExt {}

impl std::fmt::Display for HashesExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "HashesExt {{ h_e: {} }}", self.h_e)
    }
}

impl std::fmt::Debug for HashesExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Display::fmt(self, f)
    }
}

// Unit tests for the ElectionGuard extended hash.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::{
        example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters,
        guardian_secret_key::GuardianSecretKey, joint_election_public_key::JointElectionPublicKey,
    };
    use anyhow::Result;
    use hex_literal::hex;
    use util::csprng::Csprng;

    #[test]
    fn test_hashes_ext() -> Result<()> {
        let mut csprng = Csprng::new(b"test_hashes_ext");

        let election_manifest = example_election_manifest();

        let election_parameters = example_election_parameters();
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;

        let hashes = Hashes::compute(&election_parameters, &election_manifest)?;

        let guardian_secret_keys = varying_parameters
            .each_guardian_i()
            .map(|i| GuardianSecretKey::generate(&mut csprng, &election_parameters, i, None))
            .collect::<Vec<_>>();

        let guardian_public_keys = guardian_secret_keys
            .iter()
            .map(|secret_key| secret_key.make_public_key())
            .collect::<Vec<_>>();

        let joint_election_public_key =
            JointElectionPublicKey::compute(&election_parameters, &guardian_public_keys).unwrap();

        assert!(joint_election_public_key
            .as_ref()
            .is_valid(&fixed_parameters.group));

        let hashes_ext =
            HashesExt::compute(&election_parameters, &hashes, &joint_election_public_key);

        let expected_h_e = HValue::from(hex!(
            "5BFE1B5789C2F0D3C3C16D5D0F43012B5F920CC0AA61FF92B4B04C759B472F82"
        ));

        assert_eq!(hashes_ext.h_e, expected_h_e);

        Ok(())
    }
}
