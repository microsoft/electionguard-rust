// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::{
    artifacts_dir::ArtifactFile, common_utils::ElectionManifestSource,
    subcommand_helper::SubcommandHelper, subcommands::Subcommand,
};

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub(crate) enum ElectionManifestFormat {
    #[default]
    Canonical,
    Pretty,
}

/// Write the manifest to a file.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct WriteManifest {
    /// Use the pretty JSON election manifest file in the artifacts dir..
    #[arg(long)]
    pub in_pretty: bool,

    /// Use the canonical JSON election manifest file in the artifacts dir..
    #[arg(long)]
    pub in_canonical: bool,

    /// Input election manifest file. Default is the canonical JSON file in the artifacts dir.
    #[arg(long)]
    pub in_file: Option<PathBuf>,

    /// Use the built-in example election manifest.
    #[arg(long)]
    pub in_example: bool,

    /// Output format. Default is canonical.
    /// Unless `--out-file` is specified, the output is written to the appropriate file in the
    /// artifacts dir.
    #[arg(value_enum, long, default_value = "canonical")]
    pub out_format: ElectionManifestFormat,

    /// File to which to write the election manifest.
    /// Default is the appropriate election manifest file in the artifacts dir.
    /// If "-", write to stdout.
    #[arg(long)]
    out_file: Option<PathBuf>,
}

impl Subcommand for WriteManifest {
    fn uses_csprng(&self) -> bool {
        false
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let cnt_in_specified = self.in_pretty as usize
            + self.in_canonical as usize
            + self.in_file.is_some() as usize
            + self.in_example as usize;
        if cnt_in_specified > 1 {
            bail!("Specify at most one of `--in-pretty`, `--in-canonical`, `--in-file`, or `--in-example`");
        }

        // Resolve the options to a ElectionManifestSource.
        let election_manifest_source = if self.in_pretty {
            ElectionManifestSource::ArtifactFileElectionManifestPretty
        } else if self.in_example {
            ElectionManifestSource::Example
        } else if let Some(path) = self.in_file.as_ref() {
            ElectionManifestSource::SpecificFile(path.clone())
        } else {
            ElectionManifestSource::ArtifactFileElectionManifestCanonical
        };

        let election_manifest =
            election_manifest_source.load_election_manifest(&subcommand_helper.artifacts_dir)?;

        let (artifact_file, description, bytes) = match self.out_format {
            ElectionManifestFormat::Canonical => (
                ArtifactFile::ElectionManifestCanonical,
                "election manifest canonical bytes",
                election_manifest.to_canonical_bytes(),
            ),
            ElectionManifestFormat::Pretty => (
                ArtifactFile::ElectionManifestPretty,
                "election manifest pretty JSON",
                election_manifest.to_json_pretty().as_bytes().to_vec(),
            ),
        };

        let (mut bx_write, path) = subcommand_helper
            .artifacts_dir
            .out_file_stdiowrite(&self.out_file, Some(artifact_file))?;

        bx_write
            .write_all(bytes.as_slice())
            .with_context(|| format!("Writing {description} to: {}", path.display()))?;

        drop(bx_write);

        eprintln!("Wrote {description} to: {}", path.display());

        Ok(())
    }
}
