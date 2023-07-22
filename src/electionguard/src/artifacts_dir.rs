// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use eg::guardian::GuardianIndex;

/// Provides access to files in the artifacts directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArtifactFile {
    PseudorandomSeedDefeatsAllSecrecy,
    ElectionManifestPretty,
    ElectionManifestCanonical,
    ElectionParameters,
    Hashes,
    GuardianSecretKey(GuardianIndex),
    GuardianPublicKey(GuardianIndex),
    JointElectionPublicKey,
    HashesExt,
}

impl std::fmt::Display for ArtifactFile {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        PathBuf::from(*self).as_path().display().fmt(f)
    }
}

fn election_public_dir() -> PathBuf {
    "public".into()
}

fn guardian_secret_dir(i: GuardianIndex) -> PathBuf {
    format!("SECRET_for_guardian_{i}").into()
}

impl From<ArtifactFile> for PathBuf {
    fn from(artifact_file: ArtifactFile) -> PathBuf {
        use ArtifactFile::*;
        match artifact_file {
            PseudorandomSeedDefeatsAllSecrecy => {
                election_public_dir().join("pseudorandom_seed_defeats_all_secrecy.bin")
            }
            ElectionManifestPretty => election_public_dir().join("election_manifest_pretty.json"),
            ElectionManifestCanonical => {
                election_public_dir().join("election_manifest_canonical.bin")
            }
            ElectionParameters => election_public_dir().join("election_parameters.json"),
            Hashes => election_public_dir().join("hashes.json"),
            GuardianSecretKey(i) => {
                guardian_secret_dir(i).join(format!("guardian_{i}.SECRET_key.json"))
            }
            GuardianPublicKey(i) => {
                election_public_dir().join(format!("guardian_{i}.public_key.json"))
            }
            JointElectionPublicKey => election_public_dir().join("joint_election_public_key.json"),
            HashesExt => election_public_dir().join("hashes_ext.json"),
        }
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

    /// Opens the specified file for reading, or if "-" then read from stdin.
    /// Next it tries any specified artifact file.
    pub fn in_file_stdioread(
        &self,
        opt_path: &Option<PathBuf>,
        opt_artifact_file: Option<ArtifactFile>,
    ) -> Result<(Box<dyn std::io::Read>, PathBuf)> {
        let mut open_options_read = OpenOptions::new();
        open_options_read.read(true);

        let stdioread_and_path: (Box<dyn std::io::Read>, PathBuf) = if let Some(ref path) = opt_path
        {
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
            bail!("Specify at least one of opt_path or opt_artifact_file");
        };

        Ok(stdioread_and_path)
    }

    /// Opens the specified file for writing, or if "-" then write to stdout.
    /// Next it tries any specified artifact file.
    pub fn out_file_stdiowrite(
        &self,
        opt_path: &Option<PathBuf>,
        opt_artifact_file: Option<ArtifactFile>,
    ) -> Result<(Box<dyn std::io::Write>, PathBuf)> {
        let mut open_options_write = OpenOptions::new();
        open_options_write.write(true).create(true).truncate(true);

        let stdiowrite_and_path: (Box<dyn std::io::Write>, PathBuf) =
            if let Some(ref path) = opt_path {
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
                bail!("Specify at least one of opt_path or opt_artifact_file");
            };

        Ok(stdiowrite_and_path)
    }
}
