// Copyright (C) Microsoft Corporation. All rights reserved.
//     MIT License
//
//    Copyright (c) Microsoft Corporation.
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![allow(clippy::unwrap_used)]
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

#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    borrow::{
        Cow,
        //Borrow,
    },
    cell::OnceCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    ffi::OsString,
    fs::File,
    //hash::{BuildHasher, Hash, Hasher},
    io::{BufRead, BufReader, BufWriter, Cursor, Write},
    //iter::zip,
    //marker::PhantomData,
    sync::LazyLock,
    path::{Path, PathBuf},
    process::ExitCode,
    //rc::Rc,
    //str::FromStr,
    //sync::{,
        //Arc,
        //OnceLock,
    //},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use argh::FromArgs;
//use either::Either;
//use futures_lite::future::{self, FutureExt};
//use hashbrown::HashMap;
//use rand::{distr::Uniform, Rng, RngCore};
use regex::{Captures, Regex};
use rusqlite::{Connection, Result as RusqliteResult, backup::StepResult, params};
use serde_json::{Value as JsonValue, json};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    clargs::*,
    //db::*,
    files::*,
    html_writer::*,
};

//=================================================================================================|

pub(crate) fn sqlite_open_flags() -> rusqlite::OpenFlags {
    use rusqlite::OpenFlags;
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_EXRESCODE
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
}

//-------------------------------------------------------------------------------------------------|

pub(crate) fn create_in_memory_db() -> Result<Connection> {
    let open_flags = sqlite_open_flags();
    println!("Opening in-memory db");
    let db = Connection::open_in_memory_with_flags(open_flags).context("opening in-memory")?;
    db.execute_batch(include_str!("init.sql"))?;
    Ok(db)
}


//-------------------------------------------------------------------------------------------------|

pub(crate) fn save_db_to_file(db: &Connection, clargs: &Clargs, db_path: &Path) -> Result<()> {
    let Some(db_path) = &clargs.db else {
        println!("No db file specified - not saving.");
        return Ok(());
    };

    println!("Saving db to file: {}", db_path.display());
    {
        let mut db_to = Connection::open_with_flags(db_path, sqlite_open_flags())?;

        {
            use rusqlite::backup::Backup;
            let mut backup = Backup::new(db, &mut db_to)?;

            while backup.step(-1)? != StepResult::Done {}
        }

        db_to
            .close()
            .map_err(|(db_to, error)| error)
            .context("Closing db file")?;
    }
    println!("Saved db to file: {}", db_path.display());

    Ok(())
}

//-------------------------------------------------------------------------------------------------|
