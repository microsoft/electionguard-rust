// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::io::Write;

use anyhow::{Result, bail};

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
        let eg = subcommand_helper.get_eg("WriteInsecureDeterministicSeedData")?;
        let _eg = eg.as_ref();
        bail!("TODO: finish implementing WriteInsecureDeterministicSeedData");

        /*
        let mut open_options = std::fs::OpenOptions::new();
        open_options.write(true);
        if self.overwrite {
            open_options.create(true).truncate(true)
        } else {
            if subcommand_helper
                .artifacts_dir
                .exists(ArtifactFile::InsecureDeterministicPseudorandomSeedData)
            {
                bail!(
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

        println!(
            "Seed data for future insecure deterministic pseudorandom operation:\n    {}",
            &seed_data_hv
        );

        file.write_all(&seed_data_hv.0)?;
        drop(file);

        println!(
            "{} bytes written to: {}",
            seed_data_hv.0.len(),
            path.display()
        );

        Ok(())
        // */
    }
}
