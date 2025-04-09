// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(dead_code)] //? TODO: Remove temp development code

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, anyhow, bail, ensure};

use eg::{
    eg::Eg,
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    guardian_public_key::GuardianPublicKey,
    guardian_public_key_trait::GuardianKeyInfoTrait,
    guardian_secret_key::GuardianSecretKey,
    loadable::LoadableFromStdIoReadValidated,
    resource::{ProduceResource, ProduceResourceExt, Resource, ResourceFormat, ResourceIdFormat},
    resource_id::{self, ElectionDataObjectId, ResourceId},
    resource_path::ResourceNamespacePath,
};
use util::vec1::Vec1;

use crate::artifacts_dir::{ArtifactFile, ArtifactsDir};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) enum ElectionManifestSource {
    ArtifactFileElectionManifestPretty,
    ArtifactFileElectionManifestCanonical,
    SpecificFile(PathBuf),
    Example,
}

impl ElectionManifestSource {
    pub(crate) async fn load_election_manifest(
        &self,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        artifacts_dir: &ArtifactsDir,
    ) -> Result<Arc<ElectionManifest>> {
        let edo_id = ElectionDataObjectId::ElectionManifest;

        use ElectionManifestSource::*;
        let (opt_path, opt_artifact_file): (Option<PathBuf>, Option<ArtifactFile>) = match self {
            ArtifactFileElectionManifestPretty => {
                let mut resource_namespace_path = ResourceNamespacePath::try_from(edo_id)?;
                resource_namespace_path.specify_pretty();
                (None, Some(ArtifactFile::from(resource_namespace_path)))
            }
            ArtifactFileElectionManifestCanonical => {
                let mut resource_namespace_path = ResourceNamespacePath::try_from(edo_id)?;
                resource_namespace_path.specify_canonical();
                (None, Some(ArtifactFile::from(resource_namespace_path)))
            }
            SpecificFile(path) => (Some(path.clone()), None),
            Example => {
                let ridfmt = ResourceIdFormat {
                    rid: ResourceId::from(edo_id),
                    fmt: ResourceFormat::ValidElectionDataObject,
                };
                let (election_manifest, resource_source) = produce_resource
                    .produce_resource_downcast::<ElectionManifest>(&ridfmt)
                    .await?;
                ensure!(
                    resource_source.derives_from_test_data(),
                    "An example election manifest was requested but it was loaded from {resource_source} instead."
                );
                return Ok(election_manifest);
            }
        };

        let (mut stdioread, actual_path) =
            artifacts_dir.in_file_stdioread(opt_path.as_ref(), opt_artifact_file.as_ref())?;

        let election_manifest =
            ElectionManifest::from_stdioread_validated(&mut stdioread, produce_resource)
                .with_context(|| {
                    format!("Loading election manifest from: {}", actual_path.display())
                })?;

        println!(
            "Election election_manifest loaded from: {}",
            actual_path.display()
        );

        Ok(Arc::new(election_manifest))
    }
}

/*
pub(crate) fn load_election_parameters(
    produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    artifacts_dir: &ArtifactsDir,
) -> Result<ElectionParameters> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(None, Some(&ArtifactFile::ElectionParameters))?;

    let election_parameters = ElectionParameters::from_stdioread_validated(
        &mut stdioread,
        eg.csrng(),
    )?;

    println!(
        "Election election_parameters loaded from: {}",
        path.display()
    );

    Ok(election_parameters)
}
// */

/*
pub(crate) fn load_guardian_secret_key(
    produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
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
        println!(
            "Secret key for guardian number {} {:?} loaded from: {}",
            guardian_secret_key.i,
            guardian_secret_key.name,
            path.display()
        )
    } else {
        println!(
            "Secret key for guardian number {} loaded from: {}",
            guardian_secret_key.i,
            path.display()
        )
    }

    Ok(guardian_secret_key)
}
// */

/*
pub(crate) fn load_guardian_public_key(
    produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
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
        println!(
            "Public key for guardian number {} {:?} loaded from: {}",
            guardian_public_key.i(),
            gpk_name,
            path.display()
        )
    } else {
        println!(
            "Public key for guardian number {} loaded from: {}",
            guardian_public_key.i(),
            path.display()
        )
    }

    Ok(guardian_public_key)
}
// */

/*
pub(crate) fn load_joint_public_key<'vi>(
    eg: &'vi mut Eg,
    artifacts_dir: &ArtifactsDir,
) -> Result<&'vi JointPublicKey> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(None, Some(&ArtifactFile::JointPublicKey))?;

    let joint_public_key = JointPublicKey::from_stdioread_validated(
        &mut stdioread,
        produce_resource.election_parameters().await?,
    )?;
    eg.opt_joint_public_key = Some(joint_public_key);

    println!("Joint election public key loaded from: {}", path.display());

    eg
        .joint_vote_encryption_public_key_k()
        .map_err(Into::into)
}
// */

/*
pub(crate) fn load_hashes<'vi>(
    eg: &'vi mut Eg,
    artifacts_dir: &ArtifactsDir,
) -> Result<&'vi Hashes> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(None, Some(&ArtifactFile::Hashes))?;

    let hashes = Hashes::from_stdioread_validated(&mut stdioread)?;
    eg.opt_hashes = Some(hashes);

    println!("Hashes loaded from: {}", path.display());

    eg.hashes().map_err(Into::into)
}
// */

/*
pub(crate) fn load_extended_base_hash<'vi>(
    eg: &'vi mut Eg,
    artifacts_dir: &ArtifactsDir,
) -> Result<&'vi ExtendedBaseHash> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(None, Some(&ArtifactFile::ExtendedBaseHash))?;

    let extended_base_hash = ExtendedBaseHash::from_stdioread_validated(&mut stdioread)?;
    eg.opt_extended_base_hash = Some(extended_base_hash);

    println!("ExtendedBaseHash loaded from: {}", path.display());

    eg.extended_base_hash().await.map_err(Into::into)
}
// */

/*
pub(crate) fn load_pre_voting_data<'a>(
    eg: &'a mut Eg,
    artifacts_dir: &ArtifactsDir,
) -> Result<Arc<PreVotingData>> {
    let (mut stdioread, path) =
        artifacts_dir.in_file_stdioread(None, Some(&ArtifactFile::PreVotingData))?;

    let pre_voting_data = PreVotingData::from_stdioread_validated(&mut stdioread, eg)?;

    eg.opt_pre_voting_data = Some(pre_voting_data);

    println!("PreVotingData loaded from: {}", path.display());

    produce_resource.pre_voting_data().map_err(Into::into)
}
// */

/*
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

    produce_resource.guardian_public_keys().map_err(Into::into)
}
// */
