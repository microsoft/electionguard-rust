// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use eg::{
    election_manifest::ElectionManifest, example_election_manifest::example_election_manifest,
};

#[derive(Args, Debug)]
pub(crate) struct WriteManifest {
    /// File from which to read the election manifest.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Use the example election manifest.
    #[arg(long)]
    example_manifest: bool,

    /// File to which to write the (pretty JSON) representation of the election manifest.
    #[arg(long)]
    pretty: Option<PathBuf>,

    /// File to which to write the canonical representation of the election manifest.
    #[arg(long)]
    canonical: Option<PathBuf>,
}

fn write_to_pathbuf_which_may_be_stdout(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    if path == &PathBuf::from("-") {
        std::io::stdout()
            .write_all(bytes)
            .with_context(|| "Couldn't write to stdout".to_owned())
    } else {
        std::fs::write(path, bytes)
            .with_context(|| format!("Couldn't write to file: {}", path.display()))
    }
}

impl WriteManifest {
    /// Write the election manifest to a file.
    pub fn do_it(&self) -> Result<()> {
        let election_manifest = match (self.example_manifest, &self.manifest) {
            (true, None) => example_election_manifest(),
            (false, Some(path)) => {
                let bytes = std::fs::read(path).with_context(|| {
                    format!("Couldn't read from manifest file: {}", path.display())
                })?;
                ElectionManifest::from_bytes(&bytes)?
            }
            _ => bail!("Specify either `--example-manifest` or `--manifest FILE`, but not both."),
        };

        let mut did_something = false;

        if let Some(path) = self.pretty.as_ref() {
            write_to_pathbuf_which_may_be_stdout(
                path,
                election_manifest.to_json_pretty().as_bytes(),
            )?;
            did_something = true;
        }

        if let Some(path) = self.canonical.as_ref() {
            write_to_pathbuf_which_may_be_stdout(path, &election_manifest.to_canonical_bytes())?;
            did_something = true;
        }

        if !did_something {
            bail!("Specify at least one of `--pretty` or `--canonical` to get some output.")
        }

        Ok(())
    }
}
