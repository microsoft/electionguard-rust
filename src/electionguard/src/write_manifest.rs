// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;

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

impl WriteManifest {
    /// Write the election manifest to a file.
    pub fn do_it(&self) -> Result<()> {
        if self.example_manifest && self.manifest.is_some() {
            bail!("Specify either --example-manifest or --manifest, but not both.");
        }
        bail!("TODO");
        //Ok(())
    }
}
