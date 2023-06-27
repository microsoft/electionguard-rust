// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::fs::OpenOptions;
use std::io::Read;
use std::num::NonZeroU16;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};

use eg::{
    election_manifest::ElectionManifest, election_parameters::ElectionParameters,
    example_election_manifest::example_election_manifest, guardian_public_key::GuardianPublicKey,
    guardian_secret_key::GuardianSecretKey, hashes::Hashes, hashes_ext::HashesExt,
    joint_election_public_key::JointElectionPublicKey,
};
use util::csprng::Csprng;

use crate::artifacts_dir::{ArtifactFile, ArtifactsDir};

pub(crate) enum ElectionManifestSource {
    ArtifactFileElectionManifestPretty,
    ArtifactFileElectionManifestCanonical,
    SpecificFile(PathBuf),
    Example,
}

impl ElectionManifestSource {
    pub fn load_election_manifest(&self, artifacts_dir: &ArtifactsDir) -> Result<ElectionManifest> {
        let mut open_options = OpenOptions::new();
        open_options.read(true);

        let (mut file, path) = match self {
            ElectionManifestSource::ArtifactFileElectionManifestPretty => {
                artifacts_dir.open(ArtifactFile::ElectionManifestPretty, &open_options)?
            }
            ElectionManifestSource::ArtifactFileElectionManifestCanonical => {
                artifacts_dir.open(ArtifactFile::ElectionManifestCanonical, &open_options)?
            }
            ElectionManifestSource::SpecificFile(path) => {
                let file = open_options
                    .open(path)
                    .with_context(|| format!("Couldn't open manifest file: {}", path.display()))?;
                (file, path.clone())
            }
            ElectionManifestSource::Example => {
                return Ok(example_election_manifest());
            }
        };

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).with_context(|| {
            format!(
                "Couldn't read from election manifest file: {}",
                path.display()
            )
        })?;

        let election_manifest = ElectionManifest::from_bytes(&bytes)?;
        eprintln!("Election manifest loaded from: {}", path.display());

        Ok(election_manifest)
    }
}

pub(crate) fn load_election_parameters(
    artifacts_dir: &ArtifactsDir,
    csprng: &mut Csprng,
) -> Result<ElectionParameters> {
    let mut open_options = OpenOptions::new();
    open_options.read(true);

    let (mut file, path) = artifacts_dir.open(ArtifactFile::ElectionParameters, &open_options)?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).with_context(|| {
        format!(
            "Couldn't read from election parameters file: {}",
            path.display()
        )
    })?;

    let election_parameters = ElectionParameters::from_bytes(&bytes)?;
    eprintln!("Election parameters loaded from: {}", path.display());

    election_parameters.verify(csprng)?;

    Ok(election_parameters)
}

pub(crate) fn load_guardian_secret_key(
    opt_i: Option<NonZeroU16>,
    opt_secret_key_path: &Option<PathBuf>,
    artifacts_dir: &ArtifactsDir,
) -> Result<GuardianSecretKey> {
    if opt_secret_key_path.is_none() && opt_i.is_none() {
        bail!("Need at least one of the guardian `i` or secret key file path");
    }

    let (mut io_read, path) = artifacts_dir.in_file_read(
        opt_secret_key_path,
        opt_i.map(ArtifactFile::GuardianSecretKey),
    )?;

    let guardian_secret_key = GuardianSecretKey::from_reader(&mut io_read)?;

    if let Some(i) = opt_i {
        if i != guardian_secret_key.i {
            bail!(
                "Guardian number specified by --i {} does not match the guardian number {} in the secret key file: {}",
                i,
                guardian_secret_key.i,
                path.display()
            );
        }
    }

    if let Some(name) = &guardian_secret_key.opt_name {
        eprintln!(
            "Secret key for guardian number {} {:?} loaded from: {}",
            guardian_secret_key.i,
            name,
            path.display()
        )
    } else {
        eprintln!(
            "Secret key for guardian number {} loaded from: {}",
            guardian_secret_key.i,
            path.display()
        )
    }

    Ok(guardian_secret_key)
}

pub(crate) fn load_guardian_public_key(
    opt_i: Option<NonZeroU16>,
    opt_public_key_path: &Option<PathBuf>,
    artifacts_dir: &ArtifactsDir,
) -> Result<GuardianPublicKey> {
    if opt_public_key_path.is_none() && opt_i.is_none() {
        bail!("Need at least one of the guardian `i` or public key file path");
    }

    let (mut io_read, path) = artifacts_dir.in_file_read(
        opt_public_key_path,
        opt_i.map(ArtifactFile::GuardianPublicKey),
    )?;

    let guardian_public_key = GuardianPublicKey::from_reader(&mut io_read)?;

    if let Some(i) = opt_i {
        if i != guardian_public_key.i {
            bail!(
                "Guardian number specified by --i {} does not match the guardian number {} in the public key file: {}",
                i,
                guardian_public_key.i,
                path.display()
            );
        }
    }

    if let Some(name) = &guardian_public_key.opt_name {
        eprintln!(
            "Public key for guardian number {} {:?} loaded from: {}",
            guardian_public_key.i,
            name,
            path.display()
        )
    } else {
        eprintln!(
            "Public key for guardian number {} loaded from: {}",
            guardian_public_key.i,
            path.display()
        )
    }

    Ok(guardian_public_key)
}

pub(crate) fn load_joint_election_public_key(
    opt_joint_election_public_key_path: &Option<PathBuf>,
    artifacts_dir: &ArtifactsDir,
) -> Result<JointElectionPublicKey> {
    let (mut io_read, path) = artifacts_dir.in_file_read(
        opt_joint_election_public_key_path,
        Some(ArtifactFile::JointElectionPublicKey),
    )?;

    let jepk = JointElectionPublicKey::from_reader(&mut io_read)?;

    eprintln!("Joint election public key loaded from: {}", path.display());

    Ok(jepk)
}

pub(crate) fn load_hashes(
    opt_hashes_path: &Option<PathBuf>,
    opt_hashes_ext_path: &Option<PathBuf>,
    artifacts_dir: &ArtifactsDir,
) -> Result<(Hashes, HashesExt)> {
    let (mut io_read, path) =
        artifacts_dir.in_file_read(opt_hashes_path, Some(ArtifactFile::Hashes))?;
    let hashes = Hashes::from_reader(&mut io_read)?;

    eprintln!("Hashes loaded from: {}", path.display());

    let (mut io_read, path) =
        artifacts_dir.in_file_read(opt_hashes_ext_path, Some(ArtifactFile::HashesExt))?;
    let hashes_ext = HashesExt::from_reader(&mut io_read)?;

    eprintln!("Hashes (extended) loaded from: {}", path.display());

    Ok((hashes, hashes_ext))
}

/// Read the recommended amount of seed data from the OS RNG.
///
/// `OsRng` is implemented by the `getrandom` crate, which describes itself as an "Interface to
/// the operating system's random number generator."
///
/// On Linux, this uses the `getrandom` system call
/// https://man7.org/linux/man-pages/man2/getrandom.2.html
///
/// On Windows, this uses the `BCryptGenRandom` function
/// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
///
pub fn osrng_seed_data_for_csprng() -> [u8; Csprng::recommended_max_seed_bytes()] {
    let mut seed_bytes = core::array::from_fn(|_i| 0);
    OsRng.fill_bytes(&mut seed_bytes);
    seed_bytes
}
