// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::io::Write;

use anyhow::Result;

use util::hex_dump::HexDump;

use crate::{
    artifacts_dir::ArtifactFile, common_utils::osrng_seed_data_for_csprng,
    subcommand_helper::SubcommandHelper, subcommands::Subcommand,
};

#[derive(clap::Args, Debug)]
pub(crate) struct WriteRandomSeed {
    #[arg(long)]
    overwrite: bool,
}

impl Subcommand for WriteRandomSeed {
    fn uses_csprng(&self) -> bool {
        false
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut open_options = std::fs::OpenOptions::new();
        open_options.write(true);
        if self.overwrite {
            open_options.create(true).truncate(true)
        } else {
            if subcommand_helper
                .artifacts_dir
                .exists(ArtifactFile::PseudorandomSeedDefeatsAllSecrecy)
            {
                anyhow::bail!(
                    "Pseudorandom seed file already exists. Use --overwrite to overwrite it."
                );
            }

            open_options.create_new(true)
        };

        let (mut file, path) = subcommand_helper.artifacts_dir.open(
            ArtifactFile::PseudorandomSeedDefeatsAllSecrecy,
            &open_options,
        )?;

        let seed_data = osrng_seed_data_for_csprng();

        eprintln!(
            "Random seed data:\n{}",
            HexDump::new()
                .line_prefix("    ")
                .show_addr(false)
                .show_ascii(false)
                .dump(&seed_data)
        );

        file.write_all(&seed_data)?;
        eprintln!("{} bytes written to: {}", seed_data.len(), path.display());

        Ok(())
    }
}
