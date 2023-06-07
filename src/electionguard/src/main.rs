// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

mod verify_standard_parameters;
mod write_manifest;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{verify_standard_parameters::VerifyStandardParameters, write_manifest::WriteManifest};

#[derive(Parser, Debug)]
struct Clargs {
    #[command(subcommand)]
    subcmd: Subcommands,
}

#[derive(Subcommand, Debug)]
enum Subcommands {
    /// Write manifest.
    WriteManifest(WriteManifest),

    /// Verify standard parameters. Primarily for application profiling.
    VerifyStandardParameters(VerifyStandardParameters),
}

fn main() -> Result<()> {
    let clargs = Clargs::parse();

    match clargs.subcmd {
        Subcommands::WriteManifest(write_manifest) => write_manifest.do_it(),
        Subcommands::VerifyStandardParameters(verify_standard_parameters) => {
            verify_standard_parameters.do_it()
        }
    }
}
