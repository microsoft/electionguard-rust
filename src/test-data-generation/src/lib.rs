// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]
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

//! This crate is for generating test data.
//!
//! It does not depend on the [`eg`] crate, the [`eg`] crate and others may depend on it.
//!
//! However, all functionality provided by this crate requires the 'eg-allow-test-data-generation'
//! feature. It is also available for use by unit tests as they are buildt in `cfg(test)` mode.

// This is just a template to copy-and-paste to get started with new EDO types.
// It's enabled in test builds just to verify that it compiles.

//=================================================================================================|

#[cfg(any(feature = "eg-allow-test-data-generation", test))]
mod test_data_generation;

#[cfg(any(feature = "eg-allow-test-data-generation", test))]
pub use test_data_generation::*;

//=================================================================================================|

#[rustfmt::skip]
static_assertions::assert_cfg!(
    not( all( feature = "eg-allow-test-data-generation",
              feature = "eg-forbid-test-data-generation" ) ),
    r##"Can't have both features `eg-allow-test-data-generation` and
 `eg-forbid-test-data-generation` active at the same time. You may need
 to specify `default-features = false, features = [\"only\",\"specifically\",\"desired\",\"features\"]`
 in `Cargo.toml`, and/or `--no-default-features --features only,specifically,desired,features`
 on the cargo command line. In VSCode, configure the `rust-analyzer.cargo.noDefaultFeatures` and
 `rust-analyzer.cargo.features` settings."##
);
