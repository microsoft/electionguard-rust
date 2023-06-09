// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;
use util::csprng::Csprng;

use crate::{common_utils::write_to_pathbuf_which_may_be_stdout, Clargs, Subcommand};

#[derive(Args, Debug)]
pub(crate) struct Manifest {
    /// File to which to write the (pretty JSON) representation of the election manifest.
    /// If "-", write to stdout.
    #[arg(long)]
    pretty: Option<PathBuf>,

    /// File to which to write the canonical representation of the election manifest.
    /// If "-", write to stdout.
    #[arg(long)]
    canonical: Option<PathBuf>,
}

impl Subcommand for Manifest {
    fn need_csprng(&self) -> bool {
        false
    }

    fn do_it(&self, clargs: &Clargs) -> Result<()> {
        let election_manifest = clargs.load_election_manifest()?;

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

    fn do_it_with_csprng(&self, _clargs: &Clargs, _csprng: Csprng) -> Result<()> {
        bail!("call non-csprng version instead");
    }
}
