// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::fs::{File, OpenOptions};
use std::io::Stdout;
use std::path::{Path, PathBuf};
use std::string::ToString;

use anyhow::{bail, Context, Result};

/// Provides access to files in the artifacts directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArtifactFile {
    PseudorandomSeedDefeatsAllSecrecy,
    ElectionManifestPretty,
    ElectionManifestCanonical,
    ElectionParameters,
    ElectionRecordHeader,
    GuardianPrivateData(u16),
    GuardianProof(u16),
    GuardianEncryptedShares(u16, u16),
    GuardianSecretKey(u16),
    GuardianPublicKey(u16),
    Hashes,
}

impl std::fmt::Display for ArtifactFile {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        PathBuf::from(*self).as_path().display().fmt(f)
    }
}

impl From<ArtifactFile> for PathBuf {
    fn from(artifact_file: ArtifactFile) -> PathBuf {
        use ArtifactFile::*;
        match artifact_file {
            PseudorandomSeedDefeatsAllSecrecy => {
                PathBuf::from("pseudorandom_seed_defeats_all_secrecy.bin")
            }
            ElectionManifestPretty => PathBuf::from("election_manifest_pretty.json"),
            ElectionManifestCanonical => PathBuf::from("election_manifest_canonical.bin"),
            ElectionParameters => PathBuf::from("election_parameters.json"),
            ElectionRecordHeader => PathBuf::from("election_record_header.json"),
            Hashes => PathBuf::from("hashes.json"),
            GuardianPrivateData(i) => Path::new("guardians")
                .join(format!("{i}"))
                .join(format!("guardian_{i}.private_data.json")),
            GuardianProof(i) => Path::new("guardians")
                .join(format!("{i}"))
                .join(format!("guardian_{i}.proof.json")),
            GuardianEncryptedShares(i, j) => Path::new("guardians")
                .join(format!("{j}"))
                .join(format!("guardian_{i}.share.json")),
            GuardianSecretKey(i) => Path::new("guardians")
                .join(format!("{i}"))
                .join(format!("guardian_{i}.SECRET_key.json")),
            GuardianPublicKey(i) => Path::new("guardians")
                .join(format!("{i}"))
                .join(format!("guardian_{i}.public_key.json")),
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
    pub fn in_file_read(
        &self,
        opt_path: &Option<PathBuf>,
        opt_artifact_file: Option<ArtifactFile>,
    ) -> Result<(Box<dyn std::io::Read>, PathBuf)> {
        let mut open_options_read = OpenOptions::new();
        open_options_read.read(true);

        let ioread_and_path: (Box<dyn std::io::Read>, PathBuf) = if let Some(ref path) = opt_path {
            let bx_read: Box<dyn std::io::Read> = if *path == PathBuf::from("-") {
                Box::new(std::io::stdin())
            } else {
                let file = open_options_read
                    .open(path)
                    .with_context(|| format!("Couldn't open file: {}", path.display()))?;
                Box::new(file)
            };

            (bx_read, path.clone())
        } else if let Some(artifact_file) = opt_artifact_file {
            let (file, path) = self.open(artifact_file, &open_options_read)?;
            let bx_read: Box<dyn std::io::Read> = Box::new(file);
            (bx_read, path)
        } else {
            bail!("Specify at least one of opt_path or opt_artifact_file");
        };

        Ok(ioread_and_path)
    }

    /// Writes the buf to the specified file, or if "-" then write to stdout.
    /// Default is the specified artifact file.
    pub fn out_file_write(
        &self,
        out_file: &Option<PathBuf>,
        artifact_file: ArtifactFile,
        description: &str,
        buf: &[u8],
    ) -> Result<()> {
        let mut open_options_write = OpenOptions::new();
        open_options_write.write(true).create(true).truncate(true);

        let mut opt_stdout: Option<Stdout> = None;
        let mut opt_file: Option<File> = None;
        let mut opt_path: Option<PathBuf> = None;

        let dest: &mut dyn std::io::Write = if let Some(ref path) = out_file {
            if *path == PathBuf::from("-") {
                opt_stdout.insert(std::io::stdout())
            } else {
                let file = open_options_write
                    .open(path)
                    .with_context(|| format!("Couldn't open file: {}", path.display()))?;
                opt_path = Some(path.clone());
                opt_file.insert(file)
            }
        } else {
            let (file, path) = self.open(artifact_file, &open_options_write)?;
            opt_path = Some(path);
            opt_file.insert(file)
        };

        dest.write_all(buf).with_context(|| {
            if let Some(ref path) = opt_path {
                format!("Couldn't write to file: {}", path.display())
            } else {
                "Couldn't write to stdout".to_string()
            }
        })?;

        if let Some(path) = opt_path {
            eprintln!("Wrote {description} to: {}", path.display());
        }

        Ok(())
    }
}
