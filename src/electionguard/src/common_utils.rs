// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::path::PathBuf;

use anyhow::{ensure, Context, Result};

use eg::{
    election_manifest::ElectionManifest, election_parameters::ElectionParameters,
    example_election_manifest::example_election_manifest,
    example_election_parameters::example_election_parameters, guardian::GuardianIndex,
    guardian_public_key::GuardianPublicKey, guardian_public_key_trait::GuardianKeyInfoTrait,
    guardian_secret_key::GuardianSecretKey, hashes::Hashes, extended_base_hash::ExtendedBaseHash,
    joint_public_key::JointPublicKey, loadable::LoadableFromStdIoReadValidated,
    pre_voting_data::PreVotingData, eg::Eg,
};

use util::{csprng::Csprng, vec1::Vec1};

use crate::artifacts_dir::{ArtifactFile, ArtifactsDir};

#[allow(dead_code)]
pub(crate) enum ElectionManifestSource {
    ArtifactFileElectionManifestPretty,
    ArtifactFileElectionManifestCanonical,
    SpecificFile(PathBuf),
    Example,
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
                //let csprng = &mut Csprng::...;
                let eg = Eg {
                    opt_election_parameters: Some(example_election_parameters()),
                    ..Eg::default()
                };
                return Ok(example_election_manifest(&eg)?); //------- inner return
            }
        };

        let (mut stdioread, actual_path) =
            artifacts_dir.in_file_stdioread(opt_path.as_ref(), opt_artifact_file.as_ref())?;

        let election_manifest =
            ElectionManifest::from_stdioread_validated(&mut stdioread, &Eg::default())
                .with_context(|| {
                    format!("Loading election manifest from: {}", actual_path.display())
                })?;

        eprintln!(
            "Election election_manifest loaded from: {}",
            actual_path.display()
        );

        Ok(election_manifest)
    }
}

pub(crate) fn load_election_parameters(
    eg: &Eg,
    artifacts_dir: &ArtifactsDir,
) -> Result<ElectionParameters> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(None, Some(&ArtifactFile::ElectionParameters))?;

    let election_parameters = ElectionParameters::from_stdioread_validated(
        &mut stdioread,
        eg.csrng(),
    )?;

    eprintln!(
        "Election election_parameters loaded from: {}",
        path.display()
    );

    Ok(election_parameters)
}

pub(crate) fn load_guardian_secret_key(
    eg: &Eg,
    opt_i: Option<GuardianIndex>,
    opt_secret_key_path: Option<&PathBuf>,
    artifacts_dir: &ArtifactsDir,
) -> Result<GuardianSecretKey> {
    ensure!(
        opt_i.is_some() || opt_secret_key_path.is_some(),
        "Need the guardian number 'i' or secret key file path"
    );

    let (mut stdioread, path) = artifacts_dir.in_file_stdioread(
        opt_secret_key_path,
        opt_i.map(ArtifactFile::GuardianSecretKey).as_ref(),
    )?;

    let guardian_secret_key =
        <GuardianSecretKey as LoadableFromStdIoReadValidated>::from_stdioread_validated(
            &mut stdioread,
            eg,
        )?;

    if let Some(i) = opt_i {
        ensure!(i == guardian_secret_key.i,
            "Guardian number specified by --i {i} does not match the guardian number {} in the secret key file: {}",
                guardian_secret_key.i,
                path.display()
            );
    }

    if !guardian_secret_key.name.is_empty() {
        eprintln!(
            "Secret key for guardian number {} {:?} loaded from: {}",
            guardian_secret_key.i,
            guardian_secret_key.name,
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
    eg: &Eg,
    opt_i: Option<GuardianIndex>,
    opt_public_key_path: Option<&PathBuf>,
    artifacts_dir: &ArtifactsDir,
) -> Result<GuardianPublicKey> {
    ensure!(
        opt_i.is_some() || opt_public_key_path.is_some(),
        "Need the guardian number 'i' or public key file path"
    );

    let canonical_pretty = opt_canonical_pretty.unwrap_or(CanonicalPretty::Canonical);

    let (mut stdioread, path) = artifacts_dir.in_file_stdioread(
        opt_public_key_path,
        opt_i.map(ArtifactFile::GuardianPublicKey).as_ref(),
    )?;

    let guardian_public_key =
        <GuardianPublicKey as LoadableFromStdIoReadValidated>::from_stdioread_validated(
            &mut stdioread,
            eg,
        )?;

    if let Some(i) = opt_i {
        ensure!(i == guardian_public_key.i(),
                "Guardian number specified by --i {} does not match the guardian number {} in the public key file: {}",
                i,
                guardian_public_key.i(),
                path.display()
            );
    }

    let gpk_name = guardian_public_key.name();
    if !gpk_name.is_empty() {
        eprintln!(
            "Public key for guardian number {} {:?} loaded from: {}",
            guardian_public_key.i(),
            gpk_name,
            path.display()
        )
    } else {
        eprintln!(
            "Public key for guardian number {} loaded from: {}",
            guardian_public_key.i(),
            path.display()
        )
    }

    Ok(guardian_public_key)
}

pub(crate) fn load_joint_public_key<'vi>(
    eg: &'vi mut Eg,
    artifacts_dir: &ArtifactsDir,
) -> Result<&'vi JointPublicKey> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(None, Some(&ArtifactFile::JointPublicKey))?;

    let joint_public_key = JointPublicKey::from_stdioread_validated(
        &mut stdioread,
        eg.election_parameters()?,
    )?;
    eg.opt_joint_public_key = Some(joint_public_key);

    eprintln!("Joint election public key loaded from: {}", path.display());

    eg
        .joint_vote_encryption_public_key_k()
        .map_err(Into::into)
}

pub(crate) fn load_hashes<'vi>(
    eg: &'vi mut Eg,
    artifacts_dir: &ArtifactsDir,
) -> Result<&'vi Hashes> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(None, Some(&ArtifactFile::Hashes))?;

    let hashes = Hashes::from_stdioread_validated(&mut stdioread)?;
    eg.opt_hashes = Some(hashes);

    eprintln!("Hashes loaded from: {}", path.display());

    eg.hashes().map_err(Into::into)
}

pub(crate) fn load_extended_base_hash<'vi>(
    eg: &'vi mut Eg,
    artifacts_dir: &ArtifactsDir,
) -> Result<&'vi ExtendedBaseHash> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(None, Some(&ArtifactFile::ExtendedBaseHash))?;

    let extended_base_hash = ExtendedBaseHash::from_stdioread_validated(&mut stdioread)?;
    eg.opt_extended_base_hash = Some(extended_base_hash);

    eprintln!("ExtendedBaseHash loaded from: {}", path.display());

    eg.extended_base_hash().map_err(Into::into)
}

pub(crate) fn load_pre_voting_data<'a>(
    eg: &'a mut Eg,
    artifacts_dir: &ArtifactsDir,
) -> Result<&'a PreVotingData> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(None, Some(&ArtifactFile::PreVotingData))?;

    let pre_voting_data = PreVotingData::from_stdioread_validated(&mut stdioread, eg)?;

    eg.opt_pre_voting_data = Some(pre_voting_data);

    eprintln!("PreVotingData loaded from: {}", path.display());

    eg.pre_voting_data().map_err(Into::into)
}

pub(crate) fn load_all_guardian_public_keys<'vi>(
    eg: &'vi mut Eg,
    artifacts_dir: &ArtifactsDir,
) -> Result<std::cell::Ref<'vi, Vec1<GuardianPublicKey>>> {
    let mut guardian_public_keys = Vec1::<GuardianPublicKey>::new();
    let iter_guardian_ixs = eg
        .election_parameters()?
        .varying_parameters()
        .each_guardian_ix();
    for i in iter_guardian_ixs {
        let gpk = load_guardian_public_key(eg, Some(i), None, artifacts_dir)?;
        guardian_public_keys.try_push(gpk)?;
    }
    eg.refcell_opt_guardian_public_keys = Some(guardian_public_keys).into();

    eg.guardian_public_keys().map_err(Into::into)
}
