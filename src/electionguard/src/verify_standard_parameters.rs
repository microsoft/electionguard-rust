// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{bail, Result};
use clap::Args;

use util::csprng::Csprng;

use crate::{Clargs, Subcommand};

#[derive(Args, Debug)]
pub(crate) struct VerifyStandardParameters {
    #[arg(long, default_value_t = 1)]
    passes: usize,
}

impl Subcommand for VerifyStandardParameters {
    fn need_csprng(&self) -> bool {
        true
    }

    fn do_it(&self, _clargs: &Clargs) -> Result<()> {
        bail!("need csprng version instead");
    }

    fn do_it_with_csprng(&self, _clargs: &Clargs, mut csprng: Csprng) -> Result<()> {
        use eg::standard_parameters::STANDARD_PARAMETERS;

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
