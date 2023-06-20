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

use anyhow::{bail, Result};
use clap::Parser;

use artifacts_dir::{ArtifactFile, ArtifactsDir};
use subcommand_helper::SubcommandHelper;

use crate::{clargs::Clargs, subcommands::Subcommand};

fn main() -> Result<()> {
    let mut clargs = Clargs::parse();

    let insecure_deterministic_flag_passed = clargs.insecure_deterministic;

    let artifacts_dir = ArtifactsDir::new(&clargs.artifacts_dir)?;

    // Takes the `Subcommand` out of `clargs`, replacing it with the default `PrintHelp`.
    // We need it for the `self` parameter to call `do_it()`.
    let mut subcommand = std::mem::take(&mut clargs.subcommand);

    // Now we can pass ownership of `clargs` to `SubcommandInfo`.
    let mut subcommand_info = SubcommandHelper::new(clargs, artifacts_dir)?;

    let uses_csprng = Into::<&mut dyn Subcommand>::into(&mut subcommand).uses_csprng();
    subcommand_info.subcommand_uses_csprng = uses_csprng;

    if uses_csprng
        && !insecure_deterministic_flag_passed
        && subcommand_info
            .artifacts_dir
            .exists(ArtifactFile::PseudorandomSeedDefeatsAllSecrecy)
    {
        bail!("--insecure-deterministic is not set, but random seed file exists already exists in artifacts dir: {}",
            subcommand_info.artifacts_dir.path(ArtifactFile::PseudorandomSeedDefeatsAllSecrecy).display()
        );
    }

    Into::<&mut dyn Subcommand>::into(&mut subcommand).do_it(&mut subcommand_info)
}
