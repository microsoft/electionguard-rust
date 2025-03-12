// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(dead_code)] //? TODO: Remove temp development code

use std::borrow::Borrow;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use eg::{
    guardian::GuardianIndex,
    resource_category::ResourceCategory,
    resource_id::{ResourceFormat, ResourceId, ResourceIdFormat},
    resource_path::ResourceNamespacePath,
};

/// Specifies whether to use the canonical or pretty form of an artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalPretty {
    Canonical,
    Pretty,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum ArtifactFile {
    InsecureDeterministicPseudorandomSeedData,
    ResourceNamespacePath(ResourceNamespacePath),
}

impl std::fmt::Display for ArtifactFile {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactFile::InsecureDeterministicPseudorandomSeedData => {
                write!(f, "InsecureDeterministicPseudorandomSeedData")
            }
            ArtifactFile::ResourceNamespacePath(resource_namespace_path) => {
                std::fmt::Display::fmt(resource_namespace_path, f)
            }
        }
    }
}

impl std::fmt::Debug for ArtifactFile {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl From<ResourceNamespacePath> for ArtifactFile {
    /// A [`ArtifactFile`] can always be made from a [`ResourceNamespacePath`].
    #[inline]
    fn from(resource_namespace_path: ResourceNamespacePath) -> Self {
        ArtifactFile::ResourceNamespacePath(resource_namespace_path)
    }
}

/*
impl TryFrom<ResourceId> for ArtifactFile {
    type Error = anyhow::Error;
    /// Attempts to convert a [`ResourceId`] into a [`ArtifactFile`].
    #[inline]
    fn try_from(resource_id: ResourceId) -> std::result::Result<Self, Self::Error> {
        let resource_namespace_path = ResourceNamespacePath::try_from_resource_id(resource_id.clone())
            .ok_or_else(|| anyhow!("Can't figure resource namespace path from {resource_id}"))?;
        let self_ = ArtifactFile {
            resource_namespace_path,
        };
        Ok(self_)
    }
}
// */

impl TryFrom<&ArtifactFile> for PathBuf {
    type Error = anyhow::Error;
    /// Attempts to convert a [`&ArtifactFile`] into a [`PathBuf`].
    #[inline]
    fn try_from(artifact_file: &ArtifactFile) -> std::result::Result<Self, Self::Error> {
        let mut opt_resource_namespace_path = None;
        let resource_namespace_path = match artifact_file {
            ArtifactFile::InsecureDeterministicPseudorandomSeedData => {
                // We need to resolve this filename even without `cfg!(feature = "eg-allow-test-data-generation")`,
                // so we can log a warning if the file exists.
                let resource_namespace_path = ResourceNamespacePath {
                    resource_category: ResourceCategory::GeneratedTestData,
                    dir_path_components: vec![],
                    filename_base: "insecure_deterministic_seed_data".into(),
                    filename_qualifier: "".into(),
                    filename_ext: "bin".into(),
                };
                opt_resource_namespace_path.get_or_insert(resource_namespace_path)
            }
            ArtifactFile::ResourceNamespacePath(resource_namespace_path) => resource_namespace_path,
        };
        PathBuf::try_from(resource_namespace_path).map_err(|s| anyhow!("{s}"))
    }
}

/*
fn guardian_secret_dir(i: GuardianIndex) -> PathBuf {
    format!("SECRET_for_guardian_{i}").into()
}
// */

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
    pub fn path<AF: Borrow<ArtifactFile>>(&self, artifact_file: AF) -> Result<PathBuf> {
        let artifact_file: &ArtifactFile = artifact_file.borrow();
        let file_pb: PathBuf = artifact_file.try_into()?;
        let pb = self.dir_path.join(file_pb);
        Ok(pb)
    }

    /// Returns true if the file exists in the artifacts directory.
    pub fn exists<AF: Borrow<ArtifactFile>>(&self, artifact_file: AF) -> Result<bool> {
        let pb = self.path(artifact_file)?;
        pb.try_exists()
            .with_context(|| format!("Couldn't check path: {}", pb.display()))
    }

    /// Opens the specified artifact file according to the provided options.
    /// Returns the file and its path.
    pub fn open<AF: Borrow<ArtifactFile>>(
        &self,
        artifact_file: AF,
        open_options: &OpenOptions,
    ) -> Result<(File, PathBuf)> {
        let file_path = self.path(artifact_file)?;
        let file = open_options
            .open(&file_path)
            .with_context(|| format!("Couldn't open file: {}", file_path.display()))?;
        Ok((file, file_path))
    }

    /*
    /// Opens the specified artifact file according to the provided options.
    /// Returns the file and its path.
    pub fn open_read<AF: Borrow<ArtifactFile>>(
        &self,
        artifact_file: AF,
    ) -> Result<(File, PathBuf)> {
        self.open(artifact_file, OpenOptions::new().read(true))
    }
    */

    /// Opens the specified file for reading, or if "-" then read from stdin.
    /// Next it tries any specified artifact file.
    pub fn in_file_stdioread(
        &self,
        opt_path: Option<&PathBuf>,
        opt_artifact_file: Option<&ArtifactFile>,
    ) -> Result<(Box<dyn std::io::Read>, PathBuf)> {
        let mut open_options_read = OpenOptions::new();
        open_options_read.read(true);

        let stdioread_and_path: (Box<dyn std::io::Read>, PathBuf) = if let Some(path) = opt_path {
            let stdioread: Box<dyn std::io::Read> = if *path == PathBuf::from("-") {
                Box::new(std::io::stdin())
            } else {
                let file = open_options_read
                    .open(path)
                    .with_context(|| format!("Couldn't open file: {}", path.display()))?;
                Box::new(file)
            };

            (stdioread, path.clone())
        } else if let Some(artifact_file) = opt_artifact_file {
            let (file, path) = self.open(artifact_file, &open_options_read)?;
            let stdioread: Box<dyn std::io::Read> = Box::new(file);
            (stdioread, path)
        } else {
            anyhow::bail!("Specify at least one of opt_path or opt_artifact_file");
        };

        Ok(stdioread_and_path)
    }

    /// Opens the specified file for writing, or if "-" then write to stdout.
    /// Next it tries any specified artifact file.
    pub fn out_file_stdiowrite(
        &self,
        opt_path: Option<&PathBuf>,
        opt_artifact_file: Option<&ArtifactFile>,
    ) -> Result<(Box<dyn std::io::Write>, PathBuf)> {
        let mut open_options_write = OpenOptions::new();
        open_options_write.write(true).create(true).truncate(true);

        let stdiowrite_and_path: (Box<dyn std::io::Write>, PathBuf) = if let Some(path) = opt_path {
            let stdiowrite: Box<dyn std::io::Write> = if *path == PathBuf::from("-") {
                Box::new(std::io::stdout())
            } else {
                let file = open_options_write.open(path).with_context(|| {
                    format!("Couldn't open file for writing: {}", path.display())
                })?;
                Box::new(file)
            };

            (stdiowrite, path.clone())
        } else if let Some(artifact_file) = opt_artifact_file {
            let (file, path) = self.open(artifact_file, &open_options_write)?;
            let bx_write: Box<dyn std::io::Write> = Box::new(file);
            (bx_write, path)
        } else {
            anyhow::bail!("Specify at least one of opt_path or opt_artifact_file");
        };

        Ok(stdiowrite_and_path)
    }
}
