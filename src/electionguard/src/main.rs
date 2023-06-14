// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

mod common_utils;
mod guardian;
mod manifest;
mod pre_encrypted_ballots;
mod verify_standard_parameters;

use std::{path::PathBuf, time::SystemTime};

use anyhow::{bail, Context, Result};
use clap::Parser;

use eg::{
    election_manifest::ElectionManifest, example_election_manifest::example_election_manifest,
};
use util::csprng::Csprng;

use crate::{
    guardian::Guardian, manifest::Manifest, pre_encrypted_ballots::PreEncryptedBallots,
    verify_standard_parameters::VerifyStandardParameters,
};

#[derive(Parser, Debug)]
pub(crate) struct Clargs {
    /// Make the output deterministic by using the given seed.
    /// This is completely insecure and should only be used for testing.
    #[arg(long)]
    insecure_deterministic_seed: Option<String>,

    /// Election manifest file.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Use the example election manifest.
    #[arg(long)]
    example_manifest: bool,

    #[command(subcommand)]
    subcmd: Subcommands,
}

impl Clargs {
    /// Loads the election manifest based on common command line arguments.
    pub fn load_election_manifest(&self) -> Result<ElectionManifest> {
        match (self.example_manifest, &self.manifest) {
            (false, Some(path)) => {
                let bytes = std::fs::read(path).with_context(|| {
                    format!("Couldn't read from manifest file: {}", path.display())
                })?;
                ElectionManifest::from_bytes(&bytes)
            }
            (true, None) => Ok(example_election_manifest()),
            _ => bail!("Specify either `--example-manifest` or `--manifest FILE`, but not both."),
        }
    }
}

#[derive(clap::Subcommand, Debug)]
enum Subcommands {
    /// Operations on an election manifest.
    Manifest(Manifest),

    /// Verify standard parameters. Primarily for testing.
    VerifyStandardParameters(VerifyStandardParameters),

    /// Operations on preencrypted ballots.
    PreEncryptedBallots(PreEncryptedBallots),

    /// Create and manage guardians.
    Guardian(Guardian),
}

pub(crate) trait Subcommand {
    // If returns `true` the subcommand will be provided a csprng.
    fn need_csprng(&self) -> bool;

    // Call to perform the subcommand, if `need_csprng()` returned `false`.
    fn do_it(&self, clargs: &Clargs) -> Result<()>;

    //? TODO: this is kind of silly. We want to make sure the csprng is
    //? instantiated exactly 0 or 1 times, depending on the actual subcommmand.
    //? But it's tricky to enforce this statically, expecially because we
    //? have multiple shared references to clargs. However, a mutable subcommand
    //? could be handy in the future.
    //? Maybe the subcommand struct doesn't have to be the same one as the
    //? clap::Args struct.

    // Call to perform the subcommand, if `need_csprng()` returned `true`.
    fn do_it_with_csprng(&self, clargs: &Clargs, csprng: Csprng) -> Result<()>;
}

fn main() -> Result<()> {
    let clargs = Clargs::parse();

    let subcommand: &dyn Subcommand = match clargs.subcmd {
        Subcommands::Manifest(ref manifest) => manifest,
        Subcommands::PreEncryptedBallots(ref pre_ncrypted_ballots) => pre_ncrypted_ballots,
        Subcommands::Guardian(ref guardian) => guardian,
        Subcommands::VerifyStandardParameters(ref verify_standard_parameters) => {
            verify_standard_parameters
        }
    };

    if subcommand.need_csprng() {
        // eprint!("Initializing csprng...");
        // eprint!("\n!!! WARNING TEMP TEST CODE !!! ...");

        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => {
                let csprng = Csprng::new(n.as_secs() as u64);
                subcommand.do_it_with_csprng(&clargs, csprng)
            }
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        }
    } else {
        subcommand.do_it(&clargs)
    }
}
