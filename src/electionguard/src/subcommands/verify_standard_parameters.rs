// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{bail, Result};

use eg::standard_parameters::STANDARD_PARAMETERS;

use crate::{subcommand_helper::SubcommandHelper, subcommands::Subcommand};

#[derive(clap::Args, Debug)]
pub(crate) struct VerifyStandardParameters {
    #[arg(long, default_value_t = 1)]
    passes: usize,
}

impl Subcommand for VerifyStandardParameters {
    fn uses_csprng(&self) -> bool {
        true
    }

    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let mut csprng = subcommand_helper.get_csprng(b"VerifyStandardParameters")?;

        eprint!("Initializing standard parameters...");
        let fixed_parameters = &*STANDARD_PARAMETERS;
        eprintln!("Done.");

        eprintln!("Verifying standard parameters...");
        for pass in 0..self.passes {
            eprintln!("    Starting pass {pass}/{}...", self.passes);
            if !fixed_parameters.verify(&mut csprng) {
                bail!("Parameter verification failed");
            }
        }

        eprintln!("Done.");

        Ok(())
    }
}
