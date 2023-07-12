// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::num::NonZeroU16;
use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use rand_core::{OsRng, RngCore};

use eg::{
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    example_election_manifest::{
        example_election_manifest, example_election_manifest_2022_king_county,
    },
    guardian_public_key::GuardianPublicKey,
    guardian_secret_key::GuardianSecretKey,
    hashes::Hashes,
    hashes_ext::HashesExt,
    joint_election_public_key::JointElectionPublicKey,
};
use util::csprng::Csprng;

use crate::artifacts_dir::{ArtifactFile, ArtifactsDir};

pub(crate) enum ElectionManifestSource {
    ArtifactFileElectionManifestPretty,
    ArtifactFileElectionManifestCanonical,
    SpecificFile(PathBuf),
    Example,
    ExampleKingCounty2022,
}

impl ElectionManifestSource {
    pub(crate) fn load_election_manifest(
        &self,
        artifacts_dir: &ArtifactsDir,
    ) -> Result<ElectionManifest> {
        let (opt_path, opt_artifact_file): (Option<PathBuf>, Option<ArtifactFile>) = match self {
            ElectionManifestSource::ArtifactFileElectionManifestPretty => {
                (None, Some(ArtifactFile::ElectionManifestPretty))
            }
            ElectionManifestSource::ArtifactFileElectionManifestCanonical => {
                (None, Some(ArtifactFile::ElectionManifestCanonical))
            }
            ElectionManifestSource::SpecificFile(path) => (Some(path.clone()), None),
            ElectionManifestSource::Example => {
                return Ok(example_election_manifest()); //------- inner return
            }
            ElectionManifestSource::ExampleKingCounty2022 => {
                return Ok(example_election_manifest_2022_king_county()); //------- inner return
            }
        };

        let (mut stdioread, actual_path) =
            artifacts_dir.in_file_stdioread(&opt_path, opt_artifact_file)?;

        let election_manifest = ElectionManifest::from_stdioread_validated(&mut stdioread)
            .with_context(|| {
                format!("Loading election manifest from: {}", actual_path.display())
            })?;

        eprintln!("Election manifest loaded from: {}", actual_path.display());

        Ok(election_manifest)
    }
}

pub(crate) fn load_election_parameters(
    artifacts_dir: &ArtifactsDir,
    csprng: &mut Csprng,
) -> Result<ElectionParameters> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(&None, Some(ArtifactFile::ElectionParameters))?;

    let election_parameters = ElectionParameters::from_stdioread_validated(&mut stdioread, csprng)?;

    eprintln!("Election parameters loaded from: {}", path.display());

    Ok(election_parameters)
}

pub(crate) fn load_guardian_secret_key(
    opt_i: Option<NonZeroU16>,
    opt_secret_key_path: &Option<PathBuf>,
    artifacts_dir: &ArtifactsDir,
    election_parameters: &ElectionParameters,
) -> Result<GuardianSecretKey> {
    ensure!(
        opt_i.is_some() || opt_secret_key_path.is_some(),
        "Need the guardian number 'i' or secret key file path"
    );

    let (mut stdioread, path) = artifacts_dir.in_file_stdioread(
        opt_secret_key_path,
        opt_i.map(ArtifactFile::GuardianSecretKey),
    )?;

    let guardian_secret_key =
        GuardianSecretKey::from_stdioread_validated(&mut stdioread, election_parameters)?;

    if let Some(i) = opt_i {
        ensure!(i == guardian_secret_key.i,
            "Guardian number specified by --i {i} does not match the guardian number {} in the secret key file: {}",
                guardian_secret_key.i,
                path.display()
            );
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
    election_parameters: &ElectionParameters,
) -> Result<GuardianPublicKey> {
    ensure!(
        opt_i.is_some() || opt_public_key_path.is_some(),
        "Need the guardian number 'i' or public key file path"
    );

    let (mut stdioread, path) = artifacts_dir.in_file_stdioread(
        opt_public_key_path,
        opt_i.map(ArtifactFile::GuardianPublicKey),
    )?;

    let guardian_public_key =
        GuardianPublicKey::from_stdioread_validated(&mut stdioread, election_parameters)?;

    if let Some(i) = opt_i {
        ensure!(i == guardian_public_key.i,
                "Guardian number specified by --i {} does not match the guardian number {} in the public key file: {}",
                i,
                guardian_public_key.i,
                path.display()
            );
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
    artifacts_dir: &ArtifactsDir,
    election_parameters: &ElectionParameters,
) -> Result<JointElectionPublicKey> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(&None, Some(ArtifactFile::JointElectionPublicKey))?;

    let joint_election_public_key =
        JointElectionPublicKey::from_stdioread_validated(&mut stdioread, election_parameters)?;

    eprintln!("Joint election public key loaded from: {}", path.display());

    Ok(joint_election_public_key)
}

pub(crate) fn load_hashes(artifacts_dir: &ArtifactsDir) -> Result<Hashes> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(&None, Some(ArtifactFile::Hashes))?;

    let hashes = Hashes::from_stdioread_validated(&mut stdioread)?;

    eprintln!("Hashes loaded from: {}", path.display());

    Ok(hashes)
}

pub(crate) fn load_hashes_ext(artifacts_dir: &ArtifactsDir) -> Result<HashesExt> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(&None, Some(ArtifactFile::HashesExt))?;

    let hashes = HashesExt::from_stdioread_validated(&mut stdioread)?;

    eprintln!("HashesExt loaded from: {}", path.display());

    Ok(hashes)
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
pub(crate) fn osrng_seed_data_for_csprng() -> [u8; Csprng::recommended_max_seed_bytes()] {
    let mut seed_bytes = core::array::from_fn(|_i| 0);
    OsRng.fill_bytes(&mut seed_bytes);
    seed_bytes
}

pub(crate) fn load_all_guardian_public_keys(
    artifacts_dir: &ArtifactsDir,
    election_parameters: &ElectionParameters,
) -> Result<Vec<GuardianPublicKey>> {
    let mut guardian_public_keys = Vec::<GuardianPublicKey>::new();

    for i in election_parameters.varying_parameters.each_guardian_i() {
        let gpk = load_guardian_public_key(Some(i), &None, artifacts_dir, election_parameters)?;

        guardian_public_keys.push(gpk);
    }

    Ok(guardian_public_keys)
}
