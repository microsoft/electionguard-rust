// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use util::algebra::FieldElement;

use crate::{
    ballot::BallotEncrypted,
   
    election_manifest::{ContestIndex, ElectionManifest},
    election_parameters::ElectionParameters,
    guardian_public_key::GuardianPublicKey,
   
    hashes::Hashes,
   
    hashes_ext::HashesExt,
    joint_election_public_key::{Ciphertext, JointElectionPublicKey},
    verifiable_decryption::VerifiableDecryption,
    serializable::{SerializableCanonical, SerializablePretty},
};

/// The header of the election record, generated before the election begins.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreVotingData {
    /// The election manifest.
    pub manifest: ElectionManifest,

    /// Baseline election and cryptographic parameters.
    pub parameters: ElectionParameters,

    /// Hashes H_P, H_M, H_B.
    pub hashes: Hashes,

    /// Hash H_E.
    pub hashes_ext: HashesExt,

    /// The joint election public key.
    pub public_key: JointElectionPublicKey,
}

/// The body of the election record, generated after the election is complete.
#[derive(Debug)]
pub struct ElectionRecordBody {
    /// Guardian public keys including commitments and proofs of knowledge
    pub guardian_public_keys: Vec<GuardianPublicKey>,

    /// Every encrypted ballot prepared in the election (whether cast or challenged) together
    /// with its weight used in the tally.
    pub all_ballots: Vec<(BallotEncrypted, FieldElement)>,

    /// Encrypted tallies of each option
    pub encrypted_tallies: BTreeMap<ContestIndex, Vec<Ciphertext>>,

    /// Decrypted tallies with proofs of correct decryption
    pub decrypted_tallies: BTreeMap<ContestIndex, Vec<VerifiableDecryption>>,

    /// Every challenged ballot
    // challenged_ballots: Vec<BallotSelections>,

    /// Ordered lists of ballots encrypted by each device. The values are indiced of the `all_ballots`
    /// vector.
    pub ballots_by_device: HashMap<String, usize>,
}

/// The election record.
#[derive(Debug)]
pub struct ElectionRecord {
    pub prevoting: PreVotingData,
    pub body: ElectionRecordBody,
}

impl PreVotingData {
    pub fn new(
        manifest: ElectionManifest,
        parameters: ElectionParameters,
        hashes: Hashes,
        hashes_ext: HashesExt,
        public_key: JointElectionPublicKey,
    ) -> PreVotingData {
        PreVotingData {
            manifest,
            parameters,
            hashes,
            hashes_ext,
            public_key,
        }
    }

    pub fn compute(
        manifest: ElectionManifest,
        parameters: ElectionParameters,
        guardian_public_keys: &[GuardianPublicKey],
    ) -> Result<Self> {
        let joint_election_public_key =
            JointElectionPublicKey::compute(&parameters, guardian_public_keys)?;

        let hashes = Hashes::compute(&parameters, &manifest)
            .context("Could not compute hashes from election context")?;

        let hashes_ext = HashesExt::compute(&parameters, &hashes, &joint_election_public_key);

        let pre_voting_data = PreVotingData::new(
            manifest,
            parameters,
            hashes,
            hashes_ext,
            joint_election_public_key,
        );
        Ok(pre_voting_data)
    }

    pub fn set_manifest(&mut self, manifest: ElectionManifest) {
        self.manifest = manifest;
    }

    pub fn set_parameters(&mut self, parameters: ElectionParameters) {
        self.parameters = parameters;
    }

    /// Reads an `ElectionRecordHeader` from any `&str` JSON representation.
    pub fn from_json_str(json: &str) -> Result<PreVotingData> {
        serde_json::from_str(json).map_err(|e| anyhow!("Error parsing JSON: {}", e))
    }

    /// Reads an `ElectionRecordHeader` from a byte sequence.
    /// Does NOT verify that it is *the* canonical byte sequence.
    pub fn from_bytes(bytes: &[u8]) -> Result<PreVotingData> {
        serde_json::from_slice(bytes).map_err(|e| anyhow!("Error parsing canonical bytes: {}", e))
    }
}

impl SerializableCanonical for PreVotingData {}

impl SerializablePretty for PreVotingData {}
