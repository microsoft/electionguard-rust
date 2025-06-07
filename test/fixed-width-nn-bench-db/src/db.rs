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
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)] // Those are the best kind
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)]
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code

use std::ops::DerefMut;
//use std::borrow::Cow;
//use std::collections::HashSet;
//use std::convert::AsRef;
//use std::io::{BufRead, Cursor};
//use std::mem::{size_of, size_of_val};
//use std::path::{Path, PathBuf};
//use std::str::FromStr;
use std::sync::{Mutex, MutexGuard, OnceLock};

use anyhow::{anyhow, bail, ensure, Context, Result};
use chrono::{DateTime, Local};
use diesel::{connection, sql_types, table};
use diesel::prelude::*;
use diesel::sql_types::TimestamptzSqlite;
use diesel::sqlite::SqliteConnection;

//use either::Either;
//use log::{debug, error, info, trace, warn};
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};

//use crate::{};
//use crate::*;

use crate::db_models::Exe;
use crate::db_models::NewExe;

//=================================================================================================|

fn try_connect() -> Result<SqliteConnection> {
    let database_url = std::env::var("DATABASE_URL")
        .context("Env var 'DATABASE_URL' is not set")?;

    SqliteConnection::establish(&database_url)
        .with_context(|| format!("Error connecting to {database_url}"))
}

#[repr(transparent)]
pub struct DbConnLock(MutexGuard<'static, Option<SqliteConnection>>);

impl std::ops::Deref for DbConnLock {
    type Target = SqliteConnection;
    fn deref(&self) -> &Self::Target {
        // Unwrap() is justified here because we checked it before creation.
        #[allow(clippy::unwrap_used)]
        self.0.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for DbConnLock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Unwrap() is justified here because we checked it before creation.
        #[allow(clippy::unwrap_used)]
        self.0.as_mut().unwrap()
    }
}

pub fn db_conn_lock() -> Result<DbConnLock> {
    static M: Mutex<Option<SqliteConnection>> = Mutex::new(None);

    let mut mg = M.lock()
        .map_err(|err| anyhow!("DB connection Mutex poisoned: {err}"))?;

    if mg.is_none() {
        let conn = try_connect()?;
        *mg = Some(conn);
    }

    Ok(DbConnLock(mg))
}

//-------------------------------------------------------------------------------------------------|

pub fn create_exe(
    conn: &mut SqliteConnection,
    file_name: &str,
    file_path: &str,
    file_modified_time: DateTime<Local>,
    file_sha256_uchex: &str,
    file_len_bytes: i64,
) -> Result<Exe> {
    use crate::db_schema::exes;

    let new_exe = NewExe {
        file_name,
        file_path,
        file_modified_time,
        file_sha256_uchex,
        file_len_bytes,
    };

    diesel::insert_into(exes::table)
        .values(&new_exe)
        .returning(Exe::as_returning())
        .get_result(conn)
        .context("Error saving new exe")
}
