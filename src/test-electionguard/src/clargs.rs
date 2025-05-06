// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(clippy::let_and_return)] //? TODO: Remove temp development code
#![allow(clippy::needless_lifetimes)] //? TODO: Remove temp development code
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    //borrow::{
        //Cow,
        //Borrow,
    //},
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //hash::{BuildHasher, Hash, Hasher},
    //io::{BufRead, Cursor},
    //iter::zip,
    //marker::PhantomData,
    //path::{Path, PathBuf},
    //process::ExitCode,
    //sync::Arc,
    //str::FromStr,
    //sync::{
        //Arc,
        //OnceLock,
    //},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::Parser;

//=================================================================================================|

#[derive(Debug, clap::Parser)]
pub(crate) struct Clargs {
    #[arg(long)]
    pub help: bool,
    // /// An existing directory for artifacts.
    // #[arg(long, env = "ELECTIONGUARD_ARTIFACTS_DIR")]
    // pub artifacts_dir: PathBuf,

    // /// Make the entire operation deterministic by using the seed data from
    // /// the `artifacts/pseudorandom_seed_defeats_all_secrecy.bin` file.
    // /// This is completely insecure and should only be used for testing.
    // #[arg(long)]
    // pub insecure_deterministic: bool,

    // #[command(subcommand)]
    // pub subcommand: Subcommands,
}

impl Clargs {
    pub(crate) fn try_parse_from_std_env_args_os() -> Result<Clargs> {
        let self_ = Self::try_parse()?;
        Ok(self_)
    }

    pub(crate) fn maybe_print_help(&self) -> bool {
        if self.help {
            println!(
                r#"test-electionguard [OPTIONS]

--help Display this message and exit.
"#
            );
        }
        self.help
    }
}
