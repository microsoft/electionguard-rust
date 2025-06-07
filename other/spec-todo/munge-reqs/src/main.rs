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

mod clargs;
mod db;
mod files;
mod html_writer;

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

use crate::{clargs::*, db::*, files::*, html_writer::*};

//=================================================================================================|

fn main() -> ExitCode {
    match main2() {
        Ok(_) => {
            println!("Done.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e:#?}");
            ExitCode::FAILURE
        }
    }
}

fn main2() -> Result<()> {
    let clargs: Clargs = argh::from_env();

    println!("File to process: {}", clargs.file.display());

    if let Some(db_path) = &clargs.db {
        println!("File for db: {}", db_path.display());
    } else {
        println!("No db file specified.");
    }

    let db = create_in_memory_db()?;

    let mut opt_html_writer = HtmlWriter::new(&clargs)?;

    let result = fallible_stuff(&db, &clargs, &mut opt_html_writer);

    if let Some(db_path) = &clargs.db {
        let _ = save_db_to_file(&db, &clargs, db_path)
            .inspect_err(|e| eprintln!("Couldn't save db to file: {e}"));
    } else {
        println!("No db file specified - not saving.");
        return Ok(());
    }

    result.map(|_| ())
}

fn fallible_stuff(
    db: &Connection,
    clargs: &Clargs,
    opt_html_writer: &mut Option<HtmlWriter<'_>>,
) -> Result<()> {
    let read_lines_path = clargs.file.clone();

    let write_lines_path = {
        let opt_extension = read_lines_path.extension();
        let mut write_lines_path = PathBuf::clone(&read_lines_path);
        let mut new_extension: OsString = OsString::from("out");
        if let Some(extension) = read_lines_path.extension() {
            new_extension.push(".");
            new_extension.push(extension);
        }
        write_lines_path.set_extension(new_extension);
        write_lines_path
    };

    println!("Reading lines from: {}", read_lines_path.display());
    println!("Writing lines to: {}", write_lines_path.display());

    {
        let mut line_pxr = LinePxr::new(db, &read_lines_path, &write_lines_path)?;
        line_pxr.do_lines()?;

        println!("{} lines in", line_pxr.line_in_n);
        println!("{} lines out", line_pxr.line_out_n);

        // Drop `line_pxr` to flush the output file.
    }

    // Everything seems to have worked, overwrite the starting file.
    back_up_and_replace_file(&read_lines_path, &write_lines_path)?;

    if let Some(html_writer) = opt_html_writer {
        html_writer.write_html(db)?;
    }

    Ok(())
}

// These values (other than `None`) need to match the prefix, lowercased without the trailing 'j'
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Multiline {
    None,
    Xreqj,
}
impl Multiline {
    pub fn json_introducer(&self) -> String {
        format!("{self}j")
    }
}
impl std::fmt::Display for Multiline {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = format!("{self:?}");
        let mut s = s.to_lowercase();
        if s.ends_with('j') {
            s.truncate(s.len() - 1);
        }
        std::fmt::Display::fmt(&s, f)
    }
}

struct LinePxr<'c> {
    db: &'c Connection,
    read_lines_path: PathBuf,
    opt_lines: Option<std::io::Lines<BufReader<File>>>,
    line_in_n: usize,
    line_in_first_n: usize,
    line_in: String,
    line_out_n: usize,
    write_path: PathBuf,
    bufwriter: BufWriter<File>,
    cursor_string: String,
    multiline: Multiline,
}
impl<'c> LinePxr<'c> {
    fn new(db: &'c Connection, read_lines_path: &Path, write_lines_path: &Path) -> Result<Self> {
        let f_read_lines = File::open(read_lines_path.clone())
            .with_context(|| format!("Opening for reading: {}", read_lines_path.display()))?;
        let bufreader = BufReader::new(f_read_lines);
        let lines = bufreader.lines();

        let f_write_lines = File::create(write_lines_path.clone())
            .with_context(|| format!("Creating for writing: {}", write_lines_path.display()))?;
        let mut write_lines = BufWriter::new(f_write_lines);

        Ok(Self {
            db,
            read_lines_path: read_lines_path.into(),
            opt_lines: Some(lines),
            line_in_n: 0,
            line_in_first_n: 0,
            line_in: String::new(),
            line_out_n: 1,
            write_path: write_lines_path.into(),
            bufwriter: write_lines,
            cursor_string: String::new(),
            multiline: Multiline::None,
        })
    }

    fn do_lines(&mut self) -> Result<()> {
        let lines_in = self.opt_lines.take().context("lines gone")?;

        for result_line_in in lines_in {
            match result_line_in {
                Ok(line_in) => {
                    self.line_in_n += 1;
                    self.line_in = line_in.clone();
                    self.do_line(line_in)?;
                }
                Err(std_io_error) => {
                    println!("line {:4}: Error: {std_io_error}", self.line_in_n);
                    return Err(std_io_error).with_context(|| format!("line {}", self.line_in_n));
                }
            }
        }

        if !self.cursor_string.is_empty() {
            bail!(
                "Early end-of-file from construct started at line {}",
                self.line_in_first_n
            );
        }

        Ok(())
    }

    fn do_line(&mut self, line_in: String) -> Result<()> {
        let result_lines_out = if self.cursor_string.is_empty() {
            self.line_in_first_n = self.line_in_n;
            self.do_line_initial(line_in)
        } else {
            self.do_line_subsequent(line_in)
        };

        let line_in_range = format!("{}..={}", self.line_in_first_n, self.line_in_n);

        let lines_out = result_lines_out.with_context(|| format!("line {line_in_range}"))?;

        for line_out in lines_out {
            self.db
                .execute(
                    "insert into lines (line_n, line_in_range, xtext) values (?1, ?2, ?3)",
                    (&self.line_out_n, &line_in_range, &line_out),
                )
                .context("db insert into lines")?;

            writeln!(self.bufwriter, "{line_out}")?;

            self.line_out_n += 1;
        }

        Ok(())
    }

    fn do_line_initial(&mut self, line_in: String) -> Result<Vec<String>> {
        {
            //            (cap 1) (            cap 2                                      )
            // % xxxx --- S3.1.3 Election Parameters and the Election Manifest - Indices
            static S: &str = r"^\s*%+\s*(?i)[x]{4,}(?-i)\s*[-]+\s*(S\S+)\s*(.+?)\s*$";
            static RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(S).unwrap());
            if let Some(captures) = RX.captures(&line_in) {
                return self.do_line_xxxxsection_possibly_final(captures);
            }
        }
        {
            // % xxxx 8BCgdRhOK46nVaOVT77AHU4WF56ov1Noq9sGk/P+lNbDXFH92hkXYINjCdtkvUMj4h7VcBCS4c/T
            static S: &str = r"^\s*%+\s*(?i)[x]{4,}(?-i)\s?(.*?)$";
            static RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(S).unwrap());
            if let Some(captures) = RX.captures(&line_in) {
                return self.do_line_xxxx_possibly_final(captures);
            }
        }
        {
            // % xnote S2.f This section generates no unique or specific requirements
            static S: &str = r"^\s*%+\s*(?i)xnote(?-i)\s+(S\S+)\s+(.+?)\s*$";
            static RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(S).unwrap());
            if let Some(captures) = RX.captures(&line_in) {
                return self.do_line_xnote_possibly_final(captures);
            }
        }
        {
            // % xpage 60 -----------------------------------------------------------------------
            static S: &str = r"^(?i)\s*%+\s*xpage\s+-*\s*(?:pg[.]?\s*)?(\d+)\s*-*\s*(?-i)$";
            static RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(S).unwrap());
            if let Some(captures) = RX.captures(&line_in) {
                return self.do_line_xpage_possibly_final(captures);
            }
        }
        {
            // % xreq S3.a.c.b EGRI ensures that...
            // % xreq2j S3.a.c.b EGRI ensures that...
            static S: &str =
                r"^\s*%+\s*(?i)xreq(?<to_j>(?:2j)?)(?-i)\s+(?<section>S\S+)\s+(?<xtext>.+?)\s*$";
            static RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(S).unwrap());
            if let Some(captures) = RX.captures(&line_in) {
                //eprintln!("captures: {captures:?}");
                return self.do_line_xreq_possibly_final(captures);
            }
        }
        {
            // % xreqj {
            //     "section": "S1.d",
            //     "text": "EGRI provides a \"detailed implementation specification\" and/or qualifies as a \"well-documented ElectionGuard implementation\"",
            //     "sc": "ace" }
            static S: &str = r"^\s*%+\s*(?i)xreqj(?-i)\s+(.+?)$";
            static RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(S).unwrap());
            if let Some(captures) = RX.captures(&line_in) {
                return self.do_line_xreqj_initial(captures);
            }
        }
        {
            // % xtodo S0 Some descriptive text
            static S: &str = r"^\s*%+\s*(?i)xtodo(?-i)\s+(S\S+)\s+(.+?)\s*$";
            static RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(S).unwrap());
            if let Some(captures) = RX.captures(&line_in) {
                return self.do_line_xtodo_possibly_final(captures);
            }
        }
        {
            // % xdone S0 Extended base hash H_E
            static S: &str = r"^\s*%+\s*(?i)xdone(?-i)\s+(S\S+)\s+(.+?)\s*$";
            static RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(S).unwrap());
            if let Some(captures) = RX.captures(&line_in) {
                return self.do_line_xdone_possibly_final(captures);
            }
        }
        Ok(vec![line_in])
    }

    fn do_line_subsequent(&mut self, line_in: String) -> Result<Vec<String>> {
        //eprintln!("do_subsequent_line: {line_in}");

        self.cursor_string.push_str(&line_in);
        self.cursor_string.push('\n');

        match self.multiline {
            Multiline::None => {
                bail!("unexpected subsequent line {}", self.line_in);
            }
            Multiline::Xreqj => self.do_line_possibly_final(),
        }
    }

    fn do_line_xxxxsection_possibly_final<'s>(
        &mut self,
        captures: Captures<'s>,
    ) -> Result<Vec<String>> {
        let section = captures.get(1).context("capture xreq section")?.as_str();
        let title = captures.get(2).context("capture xreq text")?.as_str();

        ensure!(
            !section.is_empty(),
            "line {} xxxxsection section is empty",
            self.line_in_n
        );
        ensure!(
            !title.is_empty(),
            "line {} xxxxsection title is empty",
            self.line_in_n
        );

        self.db
            .execute(
                "insert into sections (line_n, section, title) values (?1, ?2, ?3)",
                (&self.line_out_n, section, title),
            )
            .with_context(|| {
                format!(
                    "insert sections {}, {section:?}, {title:?}",
                    &self.line_out_n
                )
            })?;

        let mut s = format!("% xxxx ---- {section} {title}");
        s.truncate(s.as_str().trim_end().len());

        let v_lines_out = vec![s];
        Ok(v_lines_out)
    }

    fn do_line_xxxx_possibly_final<'s>(&mut self, captures: Captures<'s>) -> Result<Vec<String>> {
        let data = captures.get(1).context("capture xxxx data")?.as_str();

        let mut s = format!("% xxxx {data}");
        s.truncate(s.as_str().trim_end().len());

        let v_lines_out = vec![s];
        Ok(v_lines_out)
    }

    fn do_line_xnote_possibly_final<'s>(&mut self, captures: Captures<'s>) -> Result<Vec<String>> {
        let section = captures.get(1).context("capture xnote section")?.as_str();
        let xtext = captures.get(2).context("capture xnote text")?.as_str();

        if section.is_empty() {
            return Ok(vec!["% xnote".into()]);
        }

        self.db
            .execute(
                "insert into xnotes (line_n, section, xtext) values (?1, ?2, ?3)",
                (&self.line_out_n, section, xtext),
            )
            .with_context(|| format!("insert xnotes {}, {section}, {{xtext}}", &self.line_out_n))?;

        let mut s = format!("% xnote {section} {xtext}");
        s.truncate(s.as_str().trim_end().len());

        let v_lines_out = vec![s];
        Ok(v_lines_out)
    }

    fn do_line_xpage_possibly_final<'s>(&mut self, captures: Captures<'s>) -> Result<Vec<String>> {
        let page_n = captures.get(1).context("capture page number")?.as_str();

        self.db
            .execute(
                "insert into pages (line_n, page_n) values (?1, ?2)",
                (&self.line_out_n, page_n),
            )
            .with_context(|| format!("insert pages {}, {page_n}", &self.line_out_n))?;

        let mut s = format!("% xpage ---------------------------------------- pg. {page_n} -----------------------------------------");
        let v_lines_out = vec![s];
        Ok(v_lines_out)
    }

    fn do_line_xreq_possibly_final<'s>(&mut self, captures: Captures<'s>) -> Result<Vec<String>> {
        let section = captures
            .name("section")
            .context("capture xreq section")?
            .as_str();
        let xtext = captures
            .name("xtext")
            .context("capture xreq text")?
            .as_str();
        let to_j = captures
            .name("to_j")
            .map(|s| !s.as_str().is_empty())
            .unwrap_or_default();

        ensure!(!section.is_empty(), "<section> should not be empty");
        ensure!(!xtext.is_empty(), "<xtext> should not be empty");

        let mut jv = json!({
            "section": section,
            "text": xtext,
        });

        self.handle_xreq(&mut jv, to_j)
    }

    #[allow(clippy::collapsible_if)]
    #[rustfmt::skip]
    fn handle_xreq(&mut self, jv: &mut JsonValue, as_json: bool) -> Result<Vec<String>> {
        let section = jv
            .get("section")
            .context("missing 'section'")?
            .as_str()
            .context("expecting 'section' to be a string")?;
        let xtext = jv
            .get("text")
            .context("missing 'text'")?
            .as_str()
            .context("expecting 'text' to be a string")?;
        let opt_status_code = jv
            .get("sc")
            .and_then(|sc| sc.as_str().map(|s| s.to_owned()));
        let opt_status_note: Option<String> = jv
            .get("status_note")
            .and_then(|sc| sc.as_str().map(|s| s.to_owned()));

        //eprintln!("handle_xreq  as_json: {as_json}");
        //eprintln!("handle_xreq  section: {section}");
        //eprintln!("handle_xreq  xtext: {xtext}");

        self.db
            .execute(
                "insert into xreqs (line_n, section, xtext, status_code, status_note) values (?1, ?2, ?3, ?4, ?5)",
                (&self.line_out_n, &section, &xtext, &opt_status_code, &opt_status_note),
            )
            .with_context(|| format!("insert xreqs {}, {section}, {{xtext}}", &self.line_out_n))?;

        let plain_introducer = "xreq";
        if as_json {
            if jv.get("sc").is_none() {
                jv["sc"] = json!("");
            }
            fn ensure_str_field(jv: &mut JsonValue, field: &str) {
                if jv.get(field).is_none() {
                    jv[field] = json!("");
                }
            }

            if let Some(status_code) = &opt_status_code {
                match status_code.as_str() {
                    "nfd"  => { ensure_str_field(jv, "status_note"); }
                    "ute"  => { ensure_str_field(jv, "ute");  }
                    "utep" => { ensure_str_field(jv, "utep"); }
                    "uts"  => { ensure_str_field(jv, "uts");  }
                    "utsp" => { ensure_str_field(jv, "utsp"); }
                    "its"  => { ensure_str_field(jv, "its");  }
                    "itsp" => { ensure_str_field(jv, "itsp"); }
                    _ => {}
                }
            }

            self.json_v_lines(jv, plain_introducer, as_json)
        } else {
            let mut s = format!("% {plain_introducer} {section} {xtext}");
            s.truncate(s.as_str().trim_end().len());
            Ok(vec![s])
        }
    }

    fn json_v_lines(
        &mut self,
        jv: &JsonValue,
        plain_introducer: &str,
        as_json: bool,
    ) -> Result<Vec<String>> {
        let pretty = serde_json::to_string_pretty(&jv)?;
        //eprintln!("line {} {plain_introducer}j value: {pretty}", self.line_in_n);
        let v_lines_out: Vec<String> = Cursor::new(pretty).lines().map(|r| r.unwrap()).collect();
        let mut v_lines_out = merge_json_lines(v_lines_out)?;
        //eprintln!(
        //    "line {} {plain_introducer}j value: {v_lines_out:?}",
        //    self.line_in_n
        //);
        let mut_line0 = v_lines_out.get_mut(0).context("pretty line 0")?;
        *mut_line0 = format!("% {plain_introducer}j {mut_line0}");
        Ok(v_lines_out)
    }

    fn do_line_xtodo_possibly_final<'s>(&mut self, captures: Captures<'s>) -> Result<Vec<String>> {
        let section = captures.get(1).context("capture xtodo section")?.as_str();
        let xtext = captures.get(2).context("capture xtodo text")?.as_str();

        if !section.is_empty() && !xtext.is_empty() {
            self.db
                .execute(
                    "insert into xtodos (line_n, section, xtext) values (?1, ?2, ?3)",
                    (&self.line_out_n, section, xtext),
                )
                .with_context(|| {
                    format!("insert xreqs {}, {section}, {{xtext}}", &self.line_out_n)
                })?;
        }

        let mut s = format!("% xtodo {section} {xtext}");
        s.truncate(s.as_str().trim_end().len());

        let v_lines_out = vec![s];
        Ok(v_lines_out)
    }

    fn do_line_xdone_possibly_final<'s>(&mut self, captures: Captures<'s>) -> Result<Vec<String>> {
        let section = captures.get(1).context("capture xdone section")?.as_str();
        let xtext = captures.get(2).context("capture xdone text")?.as_str();

        if !section.is_empty() && !xtext.is_empty() {
            self.db
                .execute(
                    "insert into xdones (line_n, section, xtext) values (?1, ?2, ?3)",
                    (&self.line_out_n, section, xtext),
                )
                .with_context(|| {
                    format!("insert xdones {}, {section}, {{xtext}}", &self.line_out_n)
                })?;
        }

        let mut s = format!("% xdone {section} {xtext}");
        s.truncate(s.as_str().trim_end().len());

        let v_lines_out = vec![s];
        Ok(v_lines_out)
    }

    fn do_line_xreqj_initial<'s>(&mut self, captures: Captures<'s>) -> Result<Vec<String>> {
        let xtext = captures.get(1).context("capture xreqj text")?.as_str();

        self.multiline = Multiline::Xreqj;
        self.cursor_string.push_str(xtext);
        self.cursor_string.push('\n');

        self.do_line_possibly_final()
    }

    fn do_line_possibly_final(&mut self) -> Result<Vec<String>> {
        let ml = self.multiline;
        let json_introducer = ml.json_introducer();
        let mut result_json_value = {
            let mut deserializer = serde_json::Deserializer::from_str(&self.cursor_string);
            use serde::de::Deserialize;
            JsonValue::deserialize(&mut deserializer)
        };
        match result_json_value {
            Ok(mut jv) => {
                self.multiline = Multiline::None;
                self.cursor_string.clear();
                match ml {
                    Multiline::Xreqj => self.handle_xreq(&mut jv, true),
                    _ => {
                        bail!("Expecting a different Multiline value, got {ml:?}");
                    }
                }
            }
            Err(serde_deserializer_error) => match serde_deserializer_error.classify() {
                serde_json::error::Category::Eof => Ok(vec![]),
                category => {
                    let s = format!(
                        "line {} {json_introducer} serde_deserializer_error: {category:?} {serde_deserializer_error}",
                        self.line_in_n
                    );
                    Err(serde_deserializer_error).context(s)
                }
            },
        }
    }
}

fn merge_json_lines(mut lines: Vec<String>) -> Result<Vec<String>> {
    const MAX_LINE: usize = 64;

    let mut pass_n = 0;
    let mut prev_qty_lines = usize::MAX;
    while lines.len() != prev_qty_lines {
        pass_n += 1;
        prev_qty_lines = lines.len();

        let mut line_ix = 1;
        while line_ix < lines.len() {
            let (l, r) = lines.split_at_mut(line_ix);
            let prev_line = &mut l[line_ix - 1];
            let cur_line = &r[0];

            let mut no_merge_with_prev = false;

            if !no_merge_with_prev {
                static RE_FORBID_MERGE_ONTO_CHARS: LazyLock<Regex> =
                    LazyLock::new(|| Regex::new(r#"[{\[]\s*$"#).unwrap());
                no_merge_with_prev |= RE_FORBID_MERGE_ONTO_CHARS.is_match(prev_line);
            }

            if !no_merge_with_prev {
                static RE_FORBID_MERGE_FROM_CHARS: LazyLock<Regex> =
                    LazyLock::new(|| Regex::new(r#"[:]"#).unwrap());
                no_merge_with_prev |= RE_FORBID_MERGE_FROM_CHARS.is_match(cur_line);
            }

            let cur_line = cur_line.trim();

            if !no_merge_with_prev {
                let resulting_len = prev_line.len() + 1 + cur_line.len();
                no_merge_with_prev |= MAX_LINE < resulting_len;
            }

            if !no_merge_with_prev {
                prev_line.push(' ');
                prev_line.push_str(cur_line);
                lines.remove(line_ix);
            } else {
                line_ix += 1;
            }
        }
    }

    Ok(lines)
}
