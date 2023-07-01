// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

mod artifacts_dir;
mod clargs;
mod common_utils;
mod subcommand_helper;
mod subcommands;

//use std::path::PathBuf;

use anyhow::{ensure, Result};
use clap::Parser;

use artifacts_dir::{ArtifactFile, ArtifactsDir};
use subcommand_helper::SubcommandHelper;

use crate::{clargs::Clargs, subcommands::Subcommand};

fn main() -> Result<()> {
    let mut clargs = Clargs::parse();

    let artifacts_dir = ArtifactsDir::new(&clargs.artifacts_dir)?;

    // Takes the `Subcommand` out of `clargs`, replacing it with the default `None`.
    // We need it for the `self` parameter to call `do_it()`.
    let mut subcommand = std::mem::take(&mut clargs.subcommand);
    let subcommand: &mut dyn Subcommand = (&mut subcommand).into();

    let uses_csprng = subcommand.uses_csprng();

    if uses_csprng {
        let no_seed_file = !artifacts_dir.exists(ArtifactFile::PseudorandomSeedDefeatsAllSecrecy);

        //? TODO BUG TOCTOU
        ensure!(
            no_seed_file || clargs.insecure_deterministic,
            "Pseudorandom seed file ({}) exists, but the --insecure-deterministic command line argument was not specified",
            artifacts_dir
                .path(ArtifactFile::PseudorandomSeedDefeatsAllSecrecy)
                .display()
        );
    }

    // Now we can pass ownership of `clargs` to `SubcommandHelper`.
    let mut subcommand_helper = SubcommandHelper::new(clargs, artifacts_dir, uses_csprng)?;

    // Perform the subcommand.
    subcommand.do_it(&mut subcommand_helper)
}
