// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    errors::EgResult,
    guardian_public_key::GuardianPublicKey,
    hashes::Hashes,
    hashes_ext::HashesExt,
    joint_election_public_key::JointElectionPublicKey,
    serializable::{SerializableCanonical, SerializablePretty},
};

use util::csprng::Csprng;

/// The header of the election record, generated before the election begins.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreVotingData {
    /// Baseline election and cryptographic parameters.
    pub parameters: ElectionParameters,

    /// The election manifest.
    pub manifest: ElectionManifest,

    /// Hashes H_P, H_M, H_B.
    pub hashes: Hashes,

    /// The joint election public key.
    pub public_key: JointElectionPublicKey,

    /// Hash H_E.
    pub hashes_ext: HashesExt,
}

impl PreVotingData {
    pub fn try_from_parameters_manifest_gpks(
        election_parameters: ElectionParameters,
        election_manifest: ElectionManifest,
        guardian_public_keys: &[GuardianPublicKey],
    ) -> EgResult<Self> {
        let hashes = Hashes::compute(&election_parameters, &election_manifest)?;

        let joint_election_public_key =
            JointElectionPublicKey::compute(&election_parameters, guardian_public_keys)?;

        let hashes_ext =
            HashesExt::compute(&election_parameters, &hashes, &joint_election_public_key);

        Ok(PreVotingData {
            parameters: election_parameters,
            manifest: election_manifest,
            hashes,
            public_key: joint_election_public_key,
            hashes_ext,
        })
    }

    /// Reads a `PreVotingData` from any `&str` JSON representation.
    pub fn from_json_str(json: &str) -> Result<PreVotingData> {
        serde_json::from_str(json).map_err(|e| anyhow!("Error parsing JSON: {}", e))
    }

    /// Reads a `PreVotingData` from a byte sequence.
    /// Does NOT verify that it is *the* canonical byte sequence.
    pub fn from_bytes(bytes: &[u8]) -> Result<PreVotingData> {
        serde_json::from_slice(bytes).map_err(|e| anyhow!("Error parsing canonical bytes: {}", e))
    }

    /// Reads a `PreVotingData` from a `std::io::Read` and validates it.
    pub fn from_stdioread_validated(
        stdioread: &mut dyn std::io::Read,
        csprng: &mut Csprng,
    ) -> Result<Self> {
        let mut self_: Self =
            serde_json::from_reader(stdioread).context("Reading PreVotingData")?;
        self_.validate(csprng)?;
        Ok(self_)
    }

    /// Validates that the `PreVotingData` is well-formed.
    /// You *must* call this after after deserialization for the manifest portion to be well-formed.
    pub fn validate(&mut self, csprng: &mut Csprng) -> Result<()> {
        self.parameters.validate(csprng)?;
        self.manifest.validate()?;
        self.hashes.validate()?;
        self.public_key.validate(&self.parameters)?;
        self.hashes_ext.validate()
    }

    /// Reads `HashesExt` from a `std::io::Read`.
    pub fn from_reader(io_read: &mut dyn std::io::Read) -> Result<HashesExt> {
        serde_json::from_reader(io_read)
            .map_err(|e| anyhow!("Error parsing JointElectionPublicKey: {}", e))
    }
}

impl SerializableCanonical for PreVotingData {}

impl SerializablePretty for PreVotingData {}
