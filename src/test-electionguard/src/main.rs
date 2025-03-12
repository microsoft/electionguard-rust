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

mod clargs;
mod do_test;

use std::process::exit;
use std::{pin::Pin, process::ExitCode};

use anyhow::{Context, Error, Result, anyhow, bail, ensure};
use fut_lite::FutureExt;
use futures_lite::{future as fut_lite, prelude::*, stream};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, subscriber, trace,
    trace_span, warn,
};

use crate::clargs::Clargs;

//=================================================================================================|
fn main() -> ExitCode {
    match main2() {
        Ok(exit_code) => exit_code,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
//-------------------------------------------------------------------------------------------------|
fn main2() -> Result<ExitCode> {
    let clargs = Clargs::try_parse_from_std_env_args_os()?;

    let exit_code = if clargs.maybe_print_help() {
        ExitCode::FAILURE
    } else {
        async_global_executor::init();

        let pbxf = crate::do_test::do_test(clargs).boxed();
        let pbxf = main2_uninteresting(pbxf).boxed();

        async_global_executor::block_on(pbxf);

        ExitCode::SUCCESS
    };

    Ok(exit_code)
}
//-------------------------------------------------------------------------------------------------|
async fn main2_uninteresting<T, E: Into<anyhow::Error>>(
    main3: fut_lite::Boxed<Result<T, E>>,
) -> ExitCode {
    use tracing::Level;
    use tracing_subscriber::fmt::format::FmtSpan;

    // Tracing Subscriber for logging.
    let subscriber_fmt = tracing_subscriber::fmt()
        //.with_ansi(false)
        .with_ansi(true) // default false
        //.with_file(false)
        .with_max_level(Level::DEBUG)
        //.with_max_level(Level::INFO)
        //.with_level(true)
        //.with_line_number(false)
        .with_span_events(FmtSpan::ACTIVE)
        .with_target(false)
        //.with_thread_ids(false)
        //.with_thread_names(false)
        .without_time()
        .finish();

    // Unwrap() is justified here because this is test code
    #[allow(clippy::unwrap_used)]
    tracing::subscriber::set_global_default(subscriber_fmt).unwrap();

    /*
    {
        // Print env vars
        for (key, value) in std::env::vars() {
            info!("{key}: {value}");
        }
    }
    // */

    let result = main3.await;

    let ec = match result {
        Ok(_) => {
            info!(name: "final_success", "Success!");
            ExitCode::SUCCESS
        }
        Err(into_anyhow_error) => {
            let e: anyhow::Error = into_anyhow_error.into();
            error!(name: "final_failure", "Error: {e:#}");
            ExitCode::FAILURE
        }
    };
    info!(name: "finished", "Finished, exiting with code: {ec:?}");
    ec
}
//-------------------------------------------------------------------------------------------------|
