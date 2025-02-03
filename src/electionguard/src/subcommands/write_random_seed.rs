// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::io::Write;

use anyhow::Result;

use eg::hash::HValue;

use crate::{
    artifacts_dir::ArtifactFile, subcommand_helper::SubcommandHelper, subcommands::Subcommand,
};

#[derive(clap::Args, Debug)]
pub(crate) struct WriteInsecureDeterministicSeedData {
    #[arg(long)]
    overwrite: bool,
}

impl Subcommand for WriteInsecureDeterministicSeedData {
    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut open_options = std::fs::OpenOptions::new();
        open_options.write(true);
        if self.overwrite {
            open_options.create(true).truncate(true)
        } else {
            if subcommand_helper
                .artifacts_dir
                .exists(ArtifactFile::InsecureDeterministicPseudorandomSeedData)
            {
                anyhow::bail!(
                    "Insecure deterministic seed data file already exists. Use --overwrite to overwrite it."
                );
            }

            open_options.create_new(true)
        };

        // This is just to initialize the CSPRNG from the OS random source.
        subcommand_helper.clargs.insecure_deterministic = false;

        let mut csprng = subcommand_helper
            .build_csprng()?
            .write_str("WriteInsecureDeterministicSeedData")
            .finish();

        let seed_data_hv = HValue::generate_random(csrng);

        let (mut file, path) = subcommand_helper.artifacts_dir.open(
            ArtifactFile::InsecureDeterministicPseudorandomSeedData,
            &open_options,
        )?;

        eprintln!(
            "Seed data for future insecure deterministic pseudorandom operation:\n    {}",
            &seed_data_hv
        );

        file.write_all(&seed_data_hv.0)?;
        drop(file);

        eprintln!(
            "{} bytes written to: {}",
            seed_data_hv.0.len(),
            path.display()
        );

        Ok(())
    }
}
