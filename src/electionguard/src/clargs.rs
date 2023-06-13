// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::path::PathBuf;

use crate::subcommands::Subcommands;

#[derive(Debug, clap::Parser)]
pub(crate) struct Clargs {
    /// An existing directory for artifacts.
    #[arg(long, env = "ELECTIONGUARD_ARTIFACTS_DIR")]
    pub artifacts_dir: PathBuf,

    /// Make the entire operation deterministic by using the seed data from
    /// the `artifacts/pseudorandom_seed_defeats_all_secrecy.bin` file.
    /// This is completely insecure and should only be used for testing.
    #[arg(long)]
    pub insecure_deterministic: bool,

    #[command(subcommand)]
    pub subcommand: Subcommands,
}
