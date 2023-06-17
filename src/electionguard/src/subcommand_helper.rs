// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::{fs::OpenOptions, io::Read};

use anyhow::{bail, Result};
use rand_core::{OsRng, RngCore};

use util::{csprng::Csprng, hex_dump::HexDump};

use crate::{
    artifacts_dir::{ArtifactFile, ArtifactsDir},
    clargs::Clargs,
};

/// Stuff passed to every subcommand.
/// Generally derived from the command line arguments that appear before the subcommand.
// Important: !Copy !Clone
pub(crate) struct SubcommandHelper {
    /// The command line arguments that appear before the subcommand.
    /// Note that the `subcommand` member will just be a default.
    pub clargs: Clargs,

    #[allow(dead_code)] //? TODO: Remove this
    pub artifacts_dir: ArtifactsDir,

    pub subcommand_uses_csprng: bool,

    csprng_initialized: bool,
}

impl SubcommandHelper {
    pub fn new(clargs: Clargs, artifacts_dir: ArtifactsDir) -> Result<Self> {
        Ok(Self {
            clargs,
            artifacts_dir,
            subcommand_uses_csprng: true,
            csprng_initialized: false,
        })
    }

    /// Returns the csprng initialized from the entropy source or the seed file.
    /// The csprng will be customized for the subcommand.
    /// But only once, ever, for this subcommand.
    /// We don't allow the Csprng to be initialized multiple times.
    pub fn get_csprng(&mut self, customization_data: &[u8]) -> Result<Csprng> {
        if !self.subcommand_uses_csprng {
            bail!("This subcommand is not supposed to use the Csprng");
        }

        if self.csprng_initialized {
            bail!("The Csprng has already been initialized");
        }

        self.csprng_initialized = true;

        let mut seed_data = Vec::new();
        if self.clargs.insecure_deterministic {
            let (mut file, _path) = self.artifacts_dir.open(
                ArtifactFile::PseudorandomSeedDefeatsAllSecrecy,
                OpenOptions::new().read(true),
            )?;

            file.read_to_end(&mut seed_data)?;

            eprintln!("!!! WARNING !!! Using insecure deterministic mode.");
            eprintln!(
                "Pseudorandom seed:\n{}",
                HexDump::new()
                    .line_prefix("    ")
                    .show_addr(false)
                    .show_ascii(false)
                    .dump(&seed_data)
            );
        } else {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            seed_data.extend_from_slice(&seed);
        };

        let mut seed = Vec::new();
        seed.extend_from_slice(&(seed_data.len() as u64).to_be_bytes());
        seed.extend_from_slice(seed_data.as_slice());

        seed.extend_from_slice(&(customization_data.len() as u64).to_be_bytes());
        seed.extend_from_slice(customization_data);

        Ok(Csprng::new(&seed))
    }
}
