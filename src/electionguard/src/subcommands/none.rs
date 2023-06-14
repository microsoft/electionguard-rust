// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::Result;

use crate::{subcommand_helper::SubcommandHelper, subcommands::Subcommand};

/// A subcommand that does nothing. For a default value.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct None {}

impl Subcommand for None {
    fn uses_csprng(&self) -> bool {
        false
    }

    fn do_it(&mut self, _subcommand_helper: &mut SubcommandHelper) -> Result<()> {
        Ok(())
    }
}
