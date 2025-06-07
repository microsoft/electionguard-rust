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

//use std::borrow::Cow;
//use std::collections::HashSet;
//use std::convert::AsRef;
//use std::io::{BufRead, Cursor};
//use std::mem::{size_of, size_of_val};
//use std::path::{Path, PathBuf};
//use std::str::FromStr;
//use std::sync::OnceLock;

use anyhow::{anyhow, bail, ensure, Context, Result};
use chrono::{DateTime, Local};
use diesel::prelude::*;
use diesel::sql_types::TimestamptzSqlite;
//use log::{debug, error, info, trace, warn};
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};

//use crate::{};
//use crate::*;

use super::db_schema::exes;

//=================================================================================================|

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = crate::db_schema::exes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Exe {
    pub id: i32,
    pub file_name: String,
    pub file_path: String,
    pub file_modified_time: DateTime<Local>,
    pub file_sha256_uchex: String,
    pub file_len_bytes: i64,
}

#[derive(Insertable)]
#[diesel(table_name = crate::db_schema::exes)]
pub struct NewExe<'a> {
    pub file_name: &'a str,
    pub file_path: &'a str,
    pub file_modified_time: DateTime<Local>,
    pub file_sha256_uchex: &'a str,
    pub file_len_bytes: i64,
}
