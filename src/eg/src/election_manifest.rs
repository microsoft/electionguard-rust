// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::key::Ciphertext;

/// The election manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectionManifest {
    /// All the contests in the election.
    pub contests: Vec<Contest>,
}

impl ElectionManifest {
    /// Reads an `ElectionManifest` from any `&str` JSON representation.
    pub fn from_json_str(json: &str) -> Result<ElectionManifest> {
        serde_json::from_str(json).map_err(|e| anyhow!("Error parsing JSON: {}", e))
    }

    /// Reads an `ElectionManifest` from a byte sequence.
    /// Does NOT verify that it is *the* canonical byte sequence.
    pub fn from_bytes(bytes: &[u8]) -> Result<ElectionManifest> {
        serde_json::from_slice(bytes).map_err(|e| anyhow!("Error parsing canonical bytes: {}", e))
    }

    /// Returns a pretty JSON `String` representation of the `ElectionManifest`.
    /// The final line will end with a newline.
    pub fn to_json_pretty(&self) -> String {
        // `unwrap()` is justified here because why would json serialization would fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }

    /// Returns the canonical byte sequence representation of the `ElectionManifest`.
    /// This uses a more compact JSON format.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        // `unwrap()` is justified here because why would json serialization would fail?
        #[allow(clippy::unwrap_used)]
        serde_json::to_vec(self).unwrap()
    }
}

/// A contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contest {
    /// The label.
    pub label: String,

    /// The maximum count of options that a voter may select.
    pub selection_limit: usize,

    /// The candidates/options.
    /// The order of options matches the virtual ballot.
    pub options: Vec<ContestOption>,
}

/// An option in a contest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestOption {
    /// Label
    pub label: String,
}

// Unit tests for the election manifest.
#[cfg(test)]
pub mod test {
    use super::*;
    use crate::example_election_manifest::example_election_manifest;

    #[test]
    fn test_election_manifest() {
        let election_manifest = example_election_manifest();

        let json_pretty = election_manifest.to_json_pretty();
        assert!(json_pretty.len() > 6);
        assert_eq!(json_pretty.chars().last().unwrap(), '\n');

        let canonical_bytes = election_manifest.to_canonical_bytes();
        assert!(canonical_bytes.len() > 5);
        assert_ne!(canonical_bytes[canonical_bytes.len() - 1], '\n' as u8);
        assert_ne!(canonical_bytes[canonical_bytes.len() - 1], 0x00);

        let election_manifest_from_canonical_bytes =
            ElectionManifest::from_bytes(&canonical_bytes).unwrap();

        assert_eq!(election_manifest, election_manifest_from_canonical_bytes);
    }
}
