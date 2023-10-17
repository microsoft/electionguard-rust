// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    election_parameters::ElectionParameters,
    guardian_public_key::GuardianPublicKey,
    hash::{eg_h, HValue},
    hashes::Hashes,
    joint_election_public_key::JointElectionPublicKey,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashesExt {
    /// Extended base hash.
    pub h_e: HValue,
}

impl HashesExt {
    pub fn compute(
        election_parameters: &ElectionParameters,
        hashes: &Hashes,
        joint_election_public_key: &JointElectionPublicKey,
        guardian_public_keys: &[GuardianPublicKey],
    ) -> Self {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;
        let n = varying_parameters.n.as_quantity();

        assert_eq!(guardian_public_keys.len(), n);

        // Computation of the extended base hash H_E.
        // HE = H(HB ; 0x12, K)
        // B0 = HB
        // B1 = 0x12 ∥ b(K, 512)
        // len(B1 ) = 513
        let h_e = {
            let mut v = vec![0x12];

            // K = election public key
            v.append(&mut joint_election_public_key.to_be_bytes_len_p(fixed_parameters));

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

    /// Writes a `HashesExt` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing HashesExt")
    }

    /// Reads `HashesExt` from a `std::io::Read`.
    pub fn from_reader(io_read: &mut dyn std::io::Read) -> Result<HashesExt> {
        serde_json::from_reader(io_read)
            .map_err(|e| anyhow!("Error parsing JointElectionPublicKey: {}", e))
    }

    // /// Writes a `HashesExt` to a `std::io::Write`.
    // pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
    //     let mut ser = serde_json::Serializer::pretty(stdiowrite);

    //     self.serialize(&mut ser)
    //         .context("Error writing hashes (extended)")?;

    //     ser.into_inner()
    //         .write_all(b"\n")
    //         .context("Error writing hashes (extended) file")
    // }
}

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
    use std::borrow::Borrow;
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

        assert!(joint_election_public_key.as_ref() < fixed_parameters.p.borrow());

        let hashes_ext = HashesExt::compute(
            &election_parameters,
            &hashes,
            &joint_election_public_key,
            guardian_public_keys.as_slice(),
        );

        let expected_h_e = HValue::from(hex!(
            "5541670D89498829BD3D78975D67B1B2BBF90449BB72F3B7DE847953BD6B25A8"
        ));

        #[cfg(test_hash_mismatch_warn_only)]
        {
            let cmp = |s, actual, expected| {
                if actual != expected {
                    eprintln!(
                        "\nWARNING FAILURE SUPPRESSED:\n{s}   actual: {:?}\n{s} expected: {:?}",
                        actual, expected
                    );
                }
            };
            cmp("h_e", hashes_ext.h_e, expected_h_e);
        }
        #[cfg(not(test_hash_mismatch_warn_only))]
        {
            assert_eq!(hashes_ext.h_e, expected_h_e);
        }

        Ok(())
    }
}
