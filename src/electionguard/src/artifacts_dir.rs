// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::fs::{File, OpenOptions};

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use std::string::ToString;
use strum_macros::Display;

/// Provides access to files in the artifacts directory.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum ArtifactFile {
    #[strum(to_string = "pseudorandom_seed_defeats_all_secrecy.bin")]
    PseudorandomSeedDefeatsAllSecrecy,

    #[strum(to_string = "election_manifest_pretty.json")]
    ElectionManifestPretty,

    #[strum(to_string = "election_manifest_canonical.bin")]
    ElectionManifestCanonical,
}

impl From<ArtifactFile> for PathBuf {
    fn from(artifact_file: ArtifactFile) -> PathBuf {
        artifact_file.to_string().as_str().into()
    }
}

pub(crate) struct ArtifactsDir {
    pub dir_path: PathBuf,
}

impl ArtifactsDir {
    /// Creates a new `ArtifactsDir` referring to the specified path.
    pub fn new<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        Ok(ArtifactsDir {
            dir_path: path.as_ref().to_path_buf(),
        })
    }

    /// Returns the path to the specified artifact file.
    /// Does not check whether the file exists.
    pub fn path(&self, artifact_file: ArtifactFile) -> PathBuf {
        let file_pb: PathBuf = artifact_file.into();
        self.dir_path.join(file_pb)
    }

    /// Returns true if the file exists in the artifacts directory.
    pub fn exists(&self, artifact_file: ArtifactFile) -> bool {
        self.path(artifact_file).try_exists().unwrap_or_default()
    }

    /// Opens the specified artifact file according to the provided options.
    /// Returns the file and its path.
    pub fn open(
        &self,
        artifact_file: ArtifactFile,
        open_options: &OpenOptions,
    ) -> Result<(File, PathBuf)> {
        let file_path = self.path(artifact_file);
        let file = open_options
            .open(self.path(artifact_file))
            .with_context(|| format!("Couldn't open file: {}", file_path.display()))?;
        Ok((file, file_path))
    }
}
