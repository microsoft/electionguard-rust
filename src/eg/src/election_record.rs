// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    ballot::BallotEncrypted, election_manifest::ElectionManifest,
    election_parameters::ElectionParameters, hashes::Hashes, hashes_ext::HashesExt,
    joint_election_public_key::JointElectionPublicKey,
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
#[allow(dead_code)]
/// The body of the election record, generated after the election is complete.
#[derive(Debug)]
pub struct ElectionRecordBody {
    /// Every encrypted ballot prepared in the election (whether cast or challenged)
    all_ballots: Vec<BallotEncrypted>,

    /// Every challenged ballot
    // challenged_ballots: Vec<BallotSelections>,

    /// Tally of all cast ballots

    /// Ordered lists of ballots encrypted by each device
    ballots_by_device: HashMap<String, String>,
}
#[allow(dead_code)]
/// The election record.
#[derive(Debug)]
pub struct ElectionRecord {
    prevoting: PreVotingData,
    body: ElectionRecordBody,
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

    /// Returns a pretty JSON `String` representation of the `ElectionRecordHeader`.
    /// The final line will end with a newline.
    pub fn to_json_pretty(&self) -> String {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }

    /// Returns the canonical byte sequence representation of the `ElectionRecordHeader`.
    /// This uses a more compact JSON format.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        serde_json::to_vec(self).unwrap()
    }

    /// Writes a `ElectionRecordHeader` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .context("Error writing ElectionRecordHeader")?;

        ser.into_inner()
            .write_all(b"\n")
            .context("Error writing election record header file")
    }
}
