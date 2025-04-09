// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::ops::DerefMut;

use anyhow::{Context, Result};

use eg::{
    //standard_parameters::STANDARD_PARAMETERS,
    eg::Eg,
};

use crate::{subcommand_helper::SubcommandHelper, subcommands::Subcommand};

/// Verify the standard parameters.
#[derive(clap::Args, Debug)]
pub(crate) struct VerifyStandardParameters {
    #[arg(long, default_value_t = 1)]
    passes: usize,
}

impl Subcommand for VerifyStandardParameters {
    fn do_it(&mut self, subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        let eg = subcommand_helper.get_eg("VerifyStandardParameters")?;
        let _eg = eg.as_ref();
        anyhow::bail!("TODO: finish implementing VerifyStandardParameters");

        /*
        eprint!("Initializing standard parameters...");
        let fixed_parameters = &*STANDARD_PARAMETERS;
        println!("Done.");

        println!("Verifying standard parameters...");
        for pass in 0..self.passes {
            println!("    Starting pass {pass}/{}...", self.passes);
            fixed_parameters
                .validate(eg.csrng())
                .context("Parameter verification failed")?;
        }

        println!("Done.");

        Ok(())
        // */
    }
}
