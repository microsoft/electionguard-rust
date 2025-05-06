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

use std::{path::PathBuf, str::from_utf8};
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
    pin::Pin,
    process::ExitCode,
    //process::ExitCode,
    //sync::Arc,
    //str::FromStr,
    //sync::{
        //Arc,
        //OnceLock,
    //},
};

use anyhow::{Context, Error, Result, anyhow, bail, ensure};
use async_process::Command;
use eg::election_manifest;
//use either::Either;
use fut_lite::FutureExt;
use futures_lite::{future as fut_lite, prelude::*, stream};
use itertools::Itertools;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, subscriber, trace,
    trace_span, warn,
};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::clargs::Clargs;
//=================================================================================================|
fn electionguard_exe_path() -> Result<std::path::PathBuf> {
    static EXE_FILE: &str = if cfg!(windows) {
        "electionguard.exe"
    } else {
        "electionguard"
    };

    let mut current_path = std::env::current_exe()?;
    let exe_dir = current_path.pop();
    current_path.push(EXE_FILE);

    ensure!(
        current_path.try_exists()?,
        "Can't find executable at: {}",
        current_path.display()
    );

    Ok(current_path)
}
//-------------------------------------------------------------------------------------------------|
fn electionguard_command() -> Result<Command> {
    let electionguard_exe_path = electionguard_exe_path()?;
    Ok(Command::new(electionguard_exe_path))
}
//-------------------------------------------------------------------------------------------------|
pub(crate) async fn do_electionguard_command(args: &[&str]) -> Result<()> {
    debug!("do_electionguard_command({args:?})");

    let mut command = electionguard_command()?;
    command.args(args);
    let output = command.output().await?;

    let std::process::Output {
        status,
        stdout,
        stderr,
    } = output;
    let stdout = from_utf8(&stdout)?;
    let stderr = from_utf8(&stderr)?;

    for line in stdout.lines() {
        debug!("stdout: {line}");
    }

    for line in stderr.lines() {
        debug!("stderr: {line}");
    }

    Ok(())
}
//-------------------------------------------------------------------------------------------------|
pub(crate) async fn do_test(clargs: Clargs) -> Result<()> {
    trace!("Detaching async_process::driver");
    async_global_executor::spawn(async_process::driver()).detach();

    info!("Doing test");

    do_electionguard_command(&["--help"]).await?;
    // DEBUG stdout: Usage: electionguard [OPTIONS] --artifacts-dir <ARTIFACTS_DIR> <COMMAND>
    // DEBUG stdout:
    // DEBUG stdout: Commands:
    // DEBUG stdout:   write-insecure-deterministic-seed-data
    // DEBUG stdout:           Writes some random seed data to an artifact file. Future commands will use this seed to make their operation deterministic
    // DEBUG stdout:   verify-standard-parameters
    // DEBUG stdout:           Verify standard parameters. Primarily for testing
    // DEBUG stdout:   write-parameters
    // DEBUG stdout:           Write the election parameters to a file
    // DEBUG stdout:   write-manifest
    // DEBUG stdout:           Write the election manifest to a file
    // DEBUG stdout:   write-hashes
    // DEBUG stdout:           Write the hashes to a file
    // DEBUG stdout:   guardian-secret-key-generate
    // DEBUG stdout:           Generate a guardian secret key
    // DEBUG stdout:   guardian-secret-key-write-public-key
    // DEBUG stdout:           Write a guardian public key from a guardian secret key
    // DEBUG stdout:   write-pre-voting-data
    // DEBUG stdout:           Write the pre voting data to a file
    // DEBUG stdout:   create-ballot-from-voter-selections
    // DEBUG stdout:           Produce a ballot from voter selections
    // DEBUG stdout:   help
    // DEBUG stdout:           Print this message or the help of the given subcommand(s)
    // DEBUG stdout:
    // DEBUG stdout: Options:
    // DEBUG stdout:       --artifacts-dir <ARTIFACTS_DIR>  An existing directory for artifacts [env: ELECTIONGUARD_ARTIFACTS_DIR=]
    // DEBUG stdout:       --insecure-deterministic         Make the entire operation deterministic by using the seed data from the `artifacts/pseudorandom_seed_defeats_all_secrecy.bin` file. This is completely insecure and should only be used for testing
    // DEBUG stdout:   -h, --help                           Print help

    do_electionguard_command(&["write-insecure-deterministic-seed-data"]).await?;

    Ok(())
}
//-------------------------------------------------------------------------------------------------|
