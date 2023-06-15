// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::fs::OpenOptions;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};

use eg::{
    election_manifest::ElectionManifest, election_parameters::ElectionParameters,
    example_election_manifest::example_election_manifest,
};

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

pub(crate) fn load_election_parameters(artifacts_dir: &ArtifactsDir) -> Result<ElectionParameters> {
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

    Ok(election_parameters)
}
