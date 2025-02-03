// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::expect_used)] // This is `cfg(test)` code
#![allow(clippy::manual_assert)] // This is `cfg(test)` code
#![allow(clippy::new_without_default)] // This is `cfg(test)` code
#![allow(clippy::panic)] // This is `cfg(test)` code
#![allow(clippy::unwrap_used)] // This is `cfg(test)` code
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)]
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

//use std::borrow::Cow;
//use std::collections::HashSet;
//use std::io::{BufRead, Cursor};
//use std::path::{Path, PathBuf};
//use std::str::FromStr;
//use std::sync::OnceLock;

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use log::{debug, error, info, trace, warn};
//use rand::{distr::Uniform, Rng, RngCore};

//=================================================================================================|

//pub(crate) mod problem;
//pub(crate) mod rule;
pub(crate) mod hasher;
//pub(crate) mod solution;
//pub(crate) mod sym;
//pub(crate) mod sym_set;
