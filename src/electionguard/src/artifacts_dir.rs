// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::borrow::Borrow;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use eg::guardian::GuardianIndex;

/// Specifies whether to use the canonical or pretty form of an artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalPretty {
    Canonical,
    Pretty,
}

/// Provides access to files in the artifacts directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ArtifactFile {
    InsecureDeterministicPseudorandomSeedData,
    ElectionManifestPretty,
    ElectionManifestCanonical,
    ElectionParameters,
    Hashes,
    ExtendedBaseHash,
    PreVotingData,
    GuardianSecretKey(GuardianIndex),
<<<<<<< HEAD
    GuardianPublicKey(GuardianIndex, CanonicalPretty),
    JointElectionPublicKey,
=======
    GuardianPublicKey(GuardianIndex),
    JointPublicKey,

    #[cfg(feature = "eg-allow-test-data-generation")]
    GeneratedTestDataVoterSelections(String),
    //Ballot

>>>>>>> egds-2.1-pre
    // #preencrypted_ballot#
    // PreEncryptedBallotMetadata(u128),
    // PreEncryptedBallot(u128, HValue),
    // PreEncryptedBallotNonce(u128, HValue),
    // VoterConfirmationCode(HValue),
}

impl std::fmt::Display for ArtifactFile {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        PathBuf::from(self).as_path().display().fmt(f)
    }
}

fn election_public_dir() -> PathBuf {
    "public".into()
}

fn guardian_secret_dir(i: GuardianIndex) -> PathBuf {
    format!("SECRET_for_guardian_{i}").into()
}

impl From<&ArtifactFile> for PathBuf {
    fn from(artifact_file: &ArtifactFile) -> PathBuf {
        use ArtifactFile::*;
        match artifact_file {
            InsecureDeterministicPseudorandomSeedData => {
                election_public_dir().join("insecure_deterministic_seed_data.bin")
            }
            ElectionParameters => election_public_dir().join("election_parameters.json"),
            ElectionManifestPretty => election_public_dir().join("election_manifest.json"),
            ElectionManifestCanonical => {
                election_public_dir().join("election_manifest_canonical.bin")
            }
            GuardianSecretKey(i) => {
                guardian_secret_dir(*i).join(format!("guardian_{i}.SECRET_key.json"))
            }
            GuardianPublicKey(i, canonical_pretty) => {
                let cp = match canonical_pretty {
                    CanonicalPretty::Canonical => "_canonical.bin",
                    CanonicalPretty::Pretty => ".json",
                };
                election_public_dir().join(format!("guardian_{i}.public_key{cp}.json"))
            }
            Hashes => election_public_dir().join("hashes.json"),
            JointPublicKey => election_public_dir().join("joint_public_key.json"),
            ExtendedBaseHash => election_public_dir().join("extended_base_hash.json"),
            PreVotingData => election_public_dir().join("pre_voting_data.json"),

            #[cfg(feature = "eg-allow-test-data-generation")]
            GeneratedTestDataVoterSelections(i) => election_public_dir()
                .join(format!("generated_test_data_({i}).voter_selections.json")),
            
            //Ballot(ts, hv) => election_public_dir().join("ballots").join(format!(
            //    "ballot-encrypted-{ts}-{}.json",
            //    hv.to_string_hex_no_prefix_suffix()
            //)),

            //PreEncryptedBallotMetadata(ts) => Path::new("pre_encrypted/ballots/")
            //    .join(format!("{ts}"))
            //    .join(format!("metadata.{ts}.dat")),
            //PreEncryptedBallot(ts, i) => Path::new("pre_encrypted/ballots/")
            //    .join(format!("{ts}"))
            //    .join(format!(
            //        "ballot.{}.json",
            //        i.to_string_hex_no_prefix_suffix()
            //    )),
            //PreEncryptedBallotNonce(ts, i) => Path::new("pre_encrypted/nonces/")
            //    .join(format!("{ts}"))
            //    .join(format!(
            //        "nonce.SECRET.{}.json",
            //        i.to_string_hex_no_prefix_suffix()
            //    )),
            //VoterSelection(ts, i) => Path::new("pre_encrypted/selections/")
            //    .join(format!("{ts}"))
            //    .join(format!("selection.SECRET.{}.json", i)),
            // VoterConfirmationCode(i) => Path::new("pre_encrypted").join(format!(
            //     "confirmation_code.{}.svg",
            //     i.to_string_hex_no_prefix_suffix()
            // )),
        }
    }
}

impl From<ArtifactFile> for PathBuf {
    fn from(artifact_file: ArtifactFile) -> PathBuf {
        PathBuf::from(&artifact_file)
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
    pub fn path<AF: Borrow<ArtifactFile>>(&self, artifact_file: AF) -> PathBuf {
        let file_pb: PathBuf = artifact_file.borrow().into();
        self.dir_path.join(file_pb)
    }

    /// Returns true if the file exists in the artifacts directory.
    pub fn exists<AF: Borrow<ArtifactFile>>(&self, artifact_file: AF) -> bool {
        self.path(artifact_file).try_exists().unwrap_or_default()
    }

    /// Opens the specified artifact file according to the provided options.
    /// Returns the file and its path.
    pub fn open<AF: Borrow<ArtifactFile>>(
        &self,
        artifact_file: AF,
        open_options: &OpenOptions,
    ) -> Result<(File, PathBuf)> {
        let file_path = self.path(artifact_file);
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
            bail!("Specify at least one of opt_path or opt_artifact_file");
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
            bail!("Specify at least one of opt_path or opt_artifact_file");
        };

        Ok(stdiowrite_and_path)
    }
}
