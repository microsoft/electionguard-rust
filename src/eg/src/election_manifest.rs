// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectionManifest {
    // All the contests in the election.
    pub contests: Vec<Contest>,
}

impl ElectionManifest {
    pub fn to_json_pretty(&self) -> String {
        // `unwrap()` is justified here because why would json serialization would fail?
        #[allow(clippy::unwrap_used)]
        serde_json::to_string_pretty(self).unwrap()
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        // `unwrap()` is justified here because why would json serialization would fail?
        #[allow(clippy::unwrap_used)]
        serde_json::to_vec(self).unwrap()
    }

    pub fn from_json_str(json: &str) -> Result<ElectionManifest> {
        serde_json::from_str(json).map_err(|e| anyhow!("Error parsing JSON: {}", e))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<ElectionManifest> {
        serde_json::from_slice(bytes).map_err(|e| anyhow!("Error parsing canonical bytes: {}", e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contest {
    // Label
    pub label: String,

    // The number of selections allowed.
    pub number_of_selections_allowed: usize,

    // The number of options that a voter may select.
    pub selection_limit: usize,

    // The candidates/options.
    // The order of options matches the virtual ballot.
    pub options: Vec<ContestOption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestOption {
    // Label
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
        assert_ne!(json_pretty.len(), 0);

        #[cfg(trace_extreme)]
        println!(
            r"
vvvvvvvvvvvvvvv election manifest (pretty JSON) vvvvvvvvvvvvvvv
{json_pretty}
^^^^^^^^^^^^^^^ election manifest (pretty JSON) ^^^^^^^^^^^^^^^"
        );

        let canonical_bytes = election_manifest.to_canonical_bytes();

        #[cfg(trace_extreme)]
        println!(
            r"
vvvvvvvvvvvvvvv election manifest (canonical bytes) vvvvvvvvvvvvvvv
{}
^^^^^^^^^^^^^^^ election manifest (canonical bytes) ^^^^^^^^^^^^^^^",
            util::hex_dump::HexDump::new().dump(&canonical_bytes)
        );

        assert!(canonical_bytes.len() > 0);
        assert_ne!(canonical_bytes[canonical_bytes.len() - 1], 0x00);

        let election_manifest_from_canonical_bytes =
            ElectionManifest::from_canonical_bytes(&canonical_bytes).unwrap();

        assert_eq!(election_manifest, election_manifest_from_canonical_bytes);
    }
}
