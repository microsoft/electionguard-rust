use std::collections::HashMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    ballot::{BallotDecrypted, BallotEncrypted},
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    hashes::Hashes,
    key::PublicKey,
    nizk::ProofGuardian,
};

/// The header of the election record, generated before the election begins.
#[derive(Debug, Serialize, Deserialize)]
pub struct ElectionRecordHeader {
    /// The election manifest
    pub manifest: ElectionManifest,

    /// Baseline election and cryptographic parameters
    pub parameters: ElectionParameters,

    /// Hashes H_P, H_M, H_B, and H_E
    pub hashes: Hashes,

    /// Commitments from each election guardian to each of their polynomial coefficients and
    /// proofs from each guardian of possession of each of the associated coefficients
    pub guardian_proofs: Vec<ProofGuardian>,

    /// The election public key
    public_key: PublicKey,
}

/// The body of the election record, generated after the election is complete.
#[derive(Debug)]
pub struct ElectionRecordBody {
    /// Every encrypted ballot prepared in the election (whether cast or challenged)
    all_ballots: Vec<BallotEncrypted>,

    /// Every challenged ballot
    challenged_ballots: Vec<BallotDecrypted>,

    /// Tally of all cast ballots

    /// Ordered lists of ballots encrypted by each device
    ballots_by_device: HashMap<String, String>,
}

/// The election record.
#[derive(Debug)]
pub struct ElectionRecord {
    header: ElectionRecordHeader,
    body: ElectionRecordBody,
}

impl ElectionRecordHeader {
    pub fn new(
        manifest: ElectionManifest,
        parameters: ElectionParameters,
        hashes: Hashes,
        guardian_proofs: Vec<ProofGuardian>,
        public_key: PublicKey,
    ) -> ElectionRecordHeader {
        ElectionRecordHeader {
            manifest,
            parameters,
            hashes,
            guardian_proofs,
            public_key,
        }
    }

    /// Reads an `ElectionRecordHeader` from any `&str` JSON representation.
    pub fn from_json_str(json: &str) -> Result<ElectionRecordHeader> {
        serde_json::from_str(json).map_err(|e| anyhow!("Error parsing JSON: {}", e))
    }

    /// Reads an `ElectionRecordHeader` from a byte sequence.
    /// Does NOT verify that it is *the* canonical byte sequence.
    pub fn from_bytes(bytes: &[u8]) -> Result<ElectionRecordHeader> {
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
}
