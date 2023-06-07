// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{bail, Result};
use clap::Args;

#[derive(Args, Debug)]
pub(crate) struct VerifyStandardParameters {
    #[arg(long, default_value_t = 1)]
    passes: usize,
}

impl VerifyStandardParameters {
    pub fn do_it(&self) -> Result<()> {
        use eg::standard_parameters::STANDARD_PARAMETERS;

        eprint!("Initializing csprng...");
        eprint!("\n!!! WARNING TEMP TEST CODE !!! ...");
        let mut csprng = util::csprng::Csprng::new(1234); //? TODO seed this for real
        eprintln!("Done.");

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
