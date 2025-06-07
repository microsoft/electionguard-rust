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
    //cell::RefCell,
    collections::BTreeMap, //{BTreeSet, },
    //collections::{HashSet, HashMap},
    ffi::OsString,
    fs::File,
    //hash::{BuildHasher, Hash, Hasher},
    io::{ //BufRead, Cursor
        BufWriter
        },
    //iter::zip,
    //marker::PhantomData,
    path::{Path, PathBuf},
    //rc::Rc,
    //str::FromStr,
    //sync::{,
        //Arc,
        //OnceLock,
    //},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use rusqlite::Connection;
//use either::Either;
//use futures_lite::future::{self, FutureExt};
//use hashbrown::HashMap;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use minijinja::{Environment, Value as MjValue, context};

use crate::{
    clargs::*,
    db::*,
    files::*,
    //html_writer::*,
};

//=================================================================================================|

type Cowstaticstr = Cow<'static, str>;

type CtxKey = Cowstaticstr;
type CtxValue = MjValue;
type Ctx = BTreeMap<CtxKey, CtxValue>;

pub(crate) struct HtmlWriter<'c> {
    clargs: &'c Clargs,
    html_dir_path: &'c PathBuf,
    env: Environment<'static>,
    ctx: Ctx,
}

static TEMPLATE_COMMON_CSS_NAME: &str = "common.css";
#[rustfmt::skip]
static TEMPLATE_COMMON_CSS_CONTENT: &str =
r#"        :root {
            color-scheme: light dark;
            --light-bg: white;
            --light-color: black;
            --light-link-color: blue;
            --light-table-border-color: black;
            --light-table-header-color: black;
            --dark-bg: #353535;
            --dark-color: white;
            --dark-link-color: #d2991d;
            --dark-table-border-color: #666666;
            --dark-table-header-color: #dddddd;
        }
        * {
            background-color: light-dark(var(--light-bg), var(--dark-bg));
            color: light-dark(var(--light-color), var(--dark-color));
        }
        html {
            line-height: 1.15;              /* from github.com/necolas/normalize.css */
            -webkit-text-size-adjust: 100%; /* from github.com/necolas/normalize.css */
        }
        a {
            background-color: transparent;
            color: light-dark(var(--light-link-color), var(--dark-link-color)); }
        table {
            border-collapse: collapse;
            border: 2px solid light-dark(var(--light-table-border-color), var(--dark-table-border-color)); }
        td, th {
            border: 1px solid light-dark(var(--light-table-border-color), var(--dark-table-border-color));
            padding: 1px 1px; }
        th {
            color: light-dark(var(--light-table-header-color), var(--dark-table-header-color));
            text-align: center;
        }
        td {
            /* text-align: center; */
            }
"#;

static TEMPLATE_HTML_BLOCK_RELOAD_NAME: &str = "block_reload.html";
#[rustfmt::skip]
static TEMPLATE_HTML_BLOCK_RELOAD_CONTENT: &str = 
r#"    <br/>
    <p>[<a href="">Reload</a>]&nbsp;&nbsp;&nbsp;<a href="index.html">index.html</a>
    <br/>
"#;

static TEMPLATE_HTML_HEADER_NAME: &str = "header.html";
#[rustfmt::skip]
static TEMPLATE_HTML_HEADER_CONTENT: &str =
r#"<!DOCTYPE html>
<html lang="en-US">
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>{{ title }}</title>
    <style>
{% include 'common.css' %}
    </style>
</head>
<body>
"#;

static TEMPLATE_HTML_FOOTER_NAME: &str = "footer.html";
#[rustfmt::skip]
static TEMPLATE_HTML_FOOTER_CONTENT: &str =
r#"</body>
</html>
"#;

impl<'c> HtmlWriter<'c> {
    pub fn new(clargs: &'c Clargs) -> Result<Option<Self>> {
        let Some(html_dir_path) = &clargs.html_dir else {
            println!("No HTML dir specified.");
            return Ok(None);
        };
        println!("HTML dir: {}", html_dir_path.display());

        //let html_dir_path = html_dir_path.to_path_buf();

        let html_dir_exists = html_dir_path
            .try_exists()
            .with_context(|| format!("when finding HTML dir: {}", html_dir_path.display()))?;
        ensure!(
            html_dir_exists,
            "HTML dir does not exist: {}",
            html_dir_path.display()
        );

        let metadata = std::fs::metadata(html_dir_path)
            .with_context(|| format!("when checking HTML dir: {}", html_dir_path.display()))?;
        ensure!(
            metadata.is_dir(),
            "HTML dir is not a directory: {}",
            html_dir_path.display()
        );

        let mut env = Environment::new();
        env.set_keep_trailing_newline(true);
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);

        env.add_template(TEMPLATE_COMMON_CSS_NAME, TEMPLATE_COMMON_CSS_CONTENT)?;
        env.add_template(TEMPLATE_HTML_BLOCK_RELOAD_NAME, TEMPLATE_HTML_BLOCK_RELOAD_CONTENT)?;
        env.add_template(TEMPLATE_HTML_HEADER_NAME, TEMPLATE_HTML_HEADER_CONTENT)?;
        env.add_template(TEMPLATE_HTML_FOOTER_NAME, TEMPLATE_HTML_FOOTER_CONTENT)?;

        let self_ = Self {
            clargs,
            html_dir_path,
            env,
            ctx: Ctx::new(),
        };
        Ok(Some(self_))
    }

    fn ctx_set<K, V>(&mut self, k: K, v: V) -> Option<CtxValue>
    where
        K: Into<Cowstaticstr>,
        V: Into<MjValue>,
    {
        let k = k.into();
        let v = v.into();
        self.ctx.insert(k, v)
    }

    fn query_xreqs_statuses(&mut self, db: &Connection) -> Result<()> {
        static SQL: &str = r#"
            SELECT xr.line_n, xr.section, xr.xtext, xr.status_code, xr.status_note, st.ordinal, st.xtext
            FROM xreqs xr
            LEFT OUTER JOIN xreq_statuses st ON xr.status_code = st.status_code
            ORDER BY line_n, section ASC;"#;
        let mut stmt = db.prepare(SQL)?;
        let mut row_n = 0_usize;
        let mapped_rows_iter = stmt.query_map([], |row| {
            row_n += 1;
            let row: Ctx = [
                (Cowstaticstr::from("row_n"), MjValue::from(row_n)),
                ("line_n".into(), row.get::<_, usize>(0)?.into()),
                ("section".into(), row.get::<_, String>(1)?.into()),
                ("text".into(), row.get::<_, String>(2)?.into()),
                (
                    "status_code".into(),
                    row.get::<_, Option<String>>(3)?.unwrap_or_default().into(),
                ),
                (
                    "status_note".into(),
                    row.get::<_, Option<String>>(4)?.unwrap_or_default().into(),
                ),
                (
                    "status_ordinal".into(),
                    row.get::<_, Option<usize>>(5)?.unwrap_or_default().into(),
                ),
                (
                    "status_text".into(),
                    row.get::<_, Option<String>>(6)?.unwrap_or_default().into(),
                ),
            ]
            .into_iter()
            .collect();
            Ok(row)
        })?;
        let rows = mapped_rows_iter
            .collect::<Result<Vec<_>, _>>()
            .context("querying xreqs")?;

        self.ctx.insert("xreqs_rows".into(), rows.into());
        Ok(())
    }

    fn query_xtodos_dones(&mut self, db: &Connection) -> Result<()> {
        static SQL: &str = r#"
            SELECT line_n, section, 'todo' as status, xtext FROM xtodos
            UNION ALL
            SELECT line_n, section, 'done' as status, xtext FROM xdones
            ORDER BY line_n, section ASC;"#;
        let mut stmt = db.prepare(SQL)?;
        let mut row_n = 0_usize;
        let mapped_rows_iter = stmt.query_map([], |row| {
            row_n += 1;
            let line_n: usize = row.get(0)?;
            let section: String = row.get(1)?;
            let status: String = row.get(2)?;
            let text: String = row.get(3)?;
            let row: Ctx = [
                (Cowstaticstr::from("row_n"), MjValue::from(row_n)),
                ("line_n".into(), line_n.into()),
                ("section".into(), section.into()),
                ("status".into(), status.into()),
                ("text".into(), text.into()),
            ]
            .into_iter()
            .collect();
            Ok(row)
        })?;
        let rows = mapped_rows_iter
            .collect::<Result<Vec<_>, _>>()
            .context("querying xtodos and xdones")?;
        self.ctx.insert("xtodos_rows".into(), rows.into());
        Ok(())
    }

    pub fn write_html(&mut self, db: &Connection) -> Result<()> {
        self.query_xreqs_statuses(db)?;
        self.query_xtodos_dones(db)?;
        self.write_index_html()?;
        self.write_functional_reqs_html()?;
        self.write_xreqs_html()?;
        self.write_other_items_html()?;
        self.write_xtodos_html()?;
        Ok(())
    }

    pub fn write_template_to_file(&mut self, file_path: &PathBuf, template_name: &str, template_src: &str) -> Result<String> {
        let mut file_writer = {
            let mut f = File::create(file_path)
                .with_context(|| format!("creating file: {}", file_path.display()))?;
            BufWriter::new(f)
        };

        let canonical_file_path = std::fs::canonicalize(file_path)?;
        let url = format!("file://{}", canonical_file_path.display());
        println!("url: {url}");


        let tmpl = self.env.template_from_named_str(template_name, template_src)?;
        //println!("{}", tmpl.render(&ctx)?);
        tmpl.render_to_write(&self.ctx, file_writer)?;

        Ok(url)
    }
}

impl<'c> HtmlWriter<'c> {
    pub fn write_index_html(&mut self) -> Result<String> {
        static INDEX_HTML_TITLE: &str = "EGDS 2.1.0 Functional requirements and EGRI statuses";
        static INDEX_HTML_FILENAME: &str = "index.html";

        #[rustfmt::skip]
        static INDEX_HTML_CONTENT: &str = r#"
{% include 'header.html' %}
    <h1>EGDS 2.1.0</h1>
    <p><a href="functional_reqs.html">Functional requirements and EGRI statuses</a>&nbsp;[plain: <a href="xreqs.html">xreqs.html</a>]
    <p><a href="other_items.html">Other items</a>&nbsp;[plain: <a href="xtodos.html">xtodos.html</a>]
{% include 'footer.html' %}
"#;

        let file_path: PathBuf = self.html_dir_path.join(INDEX_HTML_FILENAME);

        self.ctx_set("title", INDEX_HTML_TITLE);
        self.write_template_to_file(&file_path, INDEX_HTML_FILENAME, INDEX_HTML_CONTENT)
    }

    pub fn write_functional_reqs_html(&mut self) -> Result<String> {
        static TITLE: &str = "functional_reqs.html";
        static FILENAME: &str = "functional_reqs.html";

        #[rustfmt::skip]
        static CONTENT: &str = r#"
{% include 'header.html' %}
    {% include 'block_reload.html' %}
    <h2>EGDS v2.1.0 Functional Requirements with EGRI Statuses</h2>
    <p>[plain: <a href="xreqs.html">xreqs.html</a>]
    <table>
        <tr>
            <th>query row n</th>
            <th>doc line n</th>
            <th>section</th>
            <th>text</th>
            <th>status code</th>
            <th>status ordinal</th>
            <th>status text</th>
        </tr>
{% for row in xreqs_rows %}
        <tr>{#
            #}<td>{{ row.row_n          }}</td>{#
            #}<td>{{ row.line_n         }}</td>{#
            #}<td>{{ row.section        }}</td>{#
            #}<td>{{ row.text           }}</td>{#
            #}<td>{{ row.status_code    }}</td>{#
            #}<td>{{ row.status_ordinal }}</td>{#
            #}<td>{{ row.status_text    }}</td>{#
            #}</tr>
{% endfor %}
    </table>
    {% include 'block_reload.html' %}
{% include 'footer.html' %}
"#;

        let file_path: PathBuf = self.html_dir_path.join(FILENAME);

        self.ctx_set("title", TITLE);
        self.write_template_to_file(&file_path, FILENAME, CONTENT)
    }

    pub fn write_xreqs_html(&mut self) -> Result<String> {
        static TITLE: &str = "xreqs.html";
        static FILENAME: &str = "xreqs.html";

        #[rustfmt::skip]
        static CONTENT: &str = r#"
{% include 'header.html' %}
    <h2>xreqs</h2>
    <table>
        <tr>
            <th>query row n</th>
            <th>doc line n</th>
            <th>section</th>
            <th>status</th>
            <th>text</th>
        </tr>
{% for row in xtodos_rows %}
        <tr>{#
            #}<td>{{ row.row_n         }}</td>{#
            #}<td>{{ row.line_n         }}</td>{#
            #}<td>{{ row.section        }}</td>{#
            #}<td>{{ row.status         }}</td>{#
            #}<td>{{ row.text           }}</td>{#
            #}</tr>
{% endfor %}
    </table>
{% include 'footer.html' %}
"#;

        let file_path: PathBuf = self.html_dir_path.join(FILENAME);

        self.ctx_set("title", TITLE);
        self.write_template_to_file(&file_path, FILENAME, CONTENT)
    }

    pub fn write_other_items_html(&mut self) -> Result<String> {
        static TITLE: &str = "Other Items";
        static FILENAME: &str = "other_items.html";

        #[rustfmt::skip]
        static CONTENT: &str = r#"
{% include 'header.html' %}
    {% include 'block_reload.html' %}
    <h2>Other Items</h2>
    <p>[plain: <a href="xtodos.html">xtodos.html</a>]
    <table>
        <tr>
            <th>query row n</th>
            <th>doc line n</th>
            <th>section</th>
            <th>status</th>
            <th>text</th>
        </tr>
{% for row in xtodos_rows %}
        <tr>{#
            #}<td>{{ row.row_n         }}</td>{#
            #}<td>{{ row.line_n         }}</td>{#
            #}<td>{{ row.section        }}</td>{#
            #}<td>{{ row.status         }}</td>{#
            #}<td>{{ row.text           }}</td>{#
            #}</tr>
{% endfor %}
    </table>
    {% include 'block_reload.html' %}
{% include 'footer.html' %}
"#;

        let file_path: PathBuf = self.html_dir_path.join(FILENAME);

        self.ctx_set("title", TITLE);
        self.write_template_to_file(&file_path, FILENAME, CONTENT)
    }

    pub fn write_xtodos_html(&mut self) -> Result<String> {
        static TITLE: &str = "xtodos.html";
        static FILENAME: &str = "xtodos.html";

        #[rustfmt::skip]
        static CONTENT: &str = r#"
{% include 'header.html' %}
    <h1>xtodos</h1>
    <table>
        <tr>
            <th>query row n</th>
            <th>doc line n</th>
            <th>section</th>
            <th>status</th>
            <th>text</th>
        </tr>
{% for row in xtodos_rows %}
        <tr>{#
            #}<td>{{ row.row_n         }}</td>{#
            #}<td>{{ row.line_n         }}</td>{#
            #}<td>{{ row.section        }}</td>{#
            #}<td>{{ row.status         }}</td>{#
            #}<td>{{ row.text           }}</td>{#
            #}</tr>
{% endfor %}
    </table>
{% include 'footer.html' %}
"#;

        let file_path: PathBuf = self.html_dir_path.join(FILENAME);

        self.ctx_set("title", TITLE);
        self.write_template_to_file(&file_path, FILENAME, CONTENT)
    }

}
