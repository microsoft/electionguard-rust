// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::io::Cursor;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::contest::Contest;

/// The election manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectionManifest {
    /// All the contests in the election.
    pub contests: Vec<Contest>,
}

impl ElectionManifest {
    /// Reads a `ElectionManifest` from a `std::io::Read` and validates it.
    /// It can be either the canonical or pretty JSON representation.
    pub fn from_stdioread_validated(stdioread: &mut dyn std::io::Read) -> Result<Self> {
        let self_: Self = serde_json::from_reader(stdioread).context("Reading ElectionManifest")?;

        self_.validate()?;

        Ok(self_)
    }

    /// Validates that the `ElectionManifest` is well-formed.
    /// Useful after deserialization.
    pub fn validate(&self) -> Result<()> {
        // We currently have no validation rules for this type.
        Ok(())
    }

    /// Writes an `ElectionManifest` to a `std::io::Write` as canonical bytes.
    /// This uses a more compact JSON format.
    pub fn to_stdiowrite_canonical(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        serde_json::ser::to_writer(stdiowrite, self).context("Writing ElectionManifest canonical")
    }

    /// Returns the canonical byte sequence representation of the `ElectionManifest`.
    /// This uses a more compact JSON format.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Cursor::new(Vec::new());
        self.to_stdiowrite_canonical(&mut buf)
            .context("Writing ElectionManifest canonical")?;
        Ok(buf.into_inner())
    }

    /// Writes an `ElectionManifest` to a `std::io::Write` as pretty JSON.
    pub fn to_stdiowrite_pretty(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing ElectionManifest pretty")
    }
}

// Unit tests for the election manifest.
#[cfg(test)]
pub mod test {
    use super::*;
    use crate::example_election_manifest::example_election_manifest;

    #[test]
    fn test_election_manifest() -> Result<()> {
        let election_manifest = example_election_manifest();

        // Pretty
        {
            let mut buf = Cursor::new(vec![0u8; 0]);
            election_manifest.to_stdiowrite_pretty(&mut buf)?;

            let json_pretty = buf.into_inner();
            assert!(json_pretty.len() > 6);
            assert_eq!(*json_pretty.last().unwrap(), '\n' as u8);
        }

        // Canonical
        {
            let canonical_bytes = election_manifest.to_canonical_bytes()?;
            assert!(canonical_bytes.len() > 5);
            assert_ne!(canonical_bytes[canonical_bytes.len() - 1], '\n' as u8);
            assert_ne!(canonical_bytes[canonical_bytes.len() - 1], 0x00);

            let election_manifest_from_canonical_bytes =
                ElectionManifest::from_stdioread_validated(&mut Cursor::new(canonical_bytes))?;

            assert_eq!(election_manifest, election_manifest_from_canonical_bytes);
        }

        Ok(())
    }
}
