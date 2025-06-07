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
    //borrow::{,
        //Cow,
        //Borrow,
    //},
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    ffi::OsString,
    //hash::{BuildHasher, Hash, Hasher},
    //io::{BufRead, Cursor},
    //iter::zip,
    //marker::PhantomData,
    path::{Path, PathBuf},
    //process::ExitCode,
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
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    clargs::*,
    db::*,
    //files::*,
    html_writer::*,
};

//=================================================================================================|

pub(crate) fn hash_file<P: AsRef<Path>>(path: P, opt_name_for_msg: Option<&str>) -> Result<[u8; 32]> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();

    if let Some(name_for_msg) = opt_name_for_msg {
        let path_quoted = path.as_ref().to_string_lossy().into_owned();
        let path_quoted = shell_words::quote(&path_quoted);
        println!("For {name_for_msg} {path_quoted}:");
    };
    {
        let mut file = std::fs::File::open(&path).with_context(|| {
            let path_quoted = path.as_ref().to_string_lossy().into_owned();
            let path_quoted = shell_words::quote(&path_quoted);
            if let Some(name_for_msg) = opt_name_for_msg {
                format!("Reading {name_for_msg} {path_quoted}")
            } else {
                format!("Reading input file {path_quoted}")
            }
        })?;
        let _qty_bytes = std::io::copy(&mut file, &mut hasher)?;
        //print!(" {_qty_bytes} hashed ");
    }
    let hash_value: [u8; 32] = hasher.finalize().into();

    if opt_name_for_msg.is_some() {
        let mut s = [0u8; 64];
        faster_hex::hex_encode_upper(&hash_value, &mut s).unwrap();
        let s = std::str::from_utf8(&s).unwrap();
        println!("  SHA-3-256: {s}");
    }
    Ok(hash_value)
}

pub(crate) fn back_up_and_replace_file(read_lines_path: &Path, write_lines_path: &Path) -> Result<()> {
    //println!("Backing up file: {}", read_lines_path.display());
    let read_lines_hash = hash_file(read_lines_path, Some("input file"))?;
    let write_lines_hash = hash_file(write_lines_path, Some("output file"))?;

    if read_lines_hash == write_lines_hash {
        println!("File has not changed");
        fs_rm_file(write_lines_path)?;
        return Ok(());
    }

    let opt_old_ext = read_lines_path.extension();

    let mut opt_prev_path: Option<PathBuf> = None;
    for n in (0usize..=5).rev() {
        //println!("======== n{n}");
        let n_path = {
            let mut n_path = PathBuf::from(read_lines_path);
            if 0 < n {
                // Remove `old_ext`, if it exists
                if let Some(old_ext) = opt_old_ext {
                    //println!("n{n} old_ext(1): {old_ext:?}");
                    n_path.set_extension("");
                    //println!("n{n} n_path after set_extension(1): {}", n_path.display());
                }

                // Append `new_ext`
                let mut new_ext = OsString::from(format!("backup.{n}.bak"));
                n_path = path_filename_append_ext(n_path, new_ext)?;
                //println!("n{n} n_path after path_filename_append_ext(2): {}", n_path.display());

                // Put back `old_ext`, if it existed
                if let Some(old_ext) = opt_old_ext {
                    //println!("n{n} old_ext(2): {old_ext:?}");
                    n_path = path_filename_append_ext(n_path, old_ext)?;
                    //println!("n{n} n_path after path_filename_append_ext(3): {}", n_path.display());
                }
            }
            n_path
        };
        //println!("n{n} opt_prev_path: {opt_prev_path:?}, n_path: {n_path:?}");

        if let Some(to_path) = &opt_prev_path {
            let from_path = &n_path;
            if from_path.try_exists()? {
                //if n == 0 {
                //    fs_cp(from_path, to_path)?;
                //} else {
                fs_mv(from_path, to_path)?;
                //}
            }
        }
        opt_prev_path = Some(n_path);
    }

    // Move/rename the output file input file to overwrite the input file.
    fs_mv(write_lines_path, read_lines_path)?;

    Ok(())
}

pub(crate) fn path_filename_append_ext<P: AsRef<Path>, E: AsRef<std::ffi::OsStr>>(
    path_in: P,
    ext: E,
) -> Result<PathBuf> {
    let mut pb = path_in.as_ref().to_path_buf();
    let mut filename = pb
        .file_name()
        .context("expecting file name")?
        .to_os_string();
    filename.push(".");
    filename.push(ext);
    pb.set_file_name(filename);
    Ok(pb)
}

pub(crate) fn fs_cp<P: AsRef<Path>, Q: AsRef<Path>>(from_path: P, to_path: Q) -> Result<()> {
    fs_cp_or_mv_(true, from_path, to_path)
}

pub(crate) fn fs_mv<P: AsRef<Path>, Q: AsRef<Path>>(from_path: P, to_path: Q) -> Result<()> {
    fs_cp_or_mv_(false, from_path, to_path)
}

pub(crate) fn fs_cp_or_mv_<P: AsRef<Path>, Q: AsRef<Path>>(
    cp_not_mv: bool,
    from_path: P,
    to_path: Q,
) -> Result<()> {
    let action = ["mv", "cp"][cp_not_mv as usize];
    let from_path_quoted = from_path.as_ref().to_string_lossy().into_owned();
    let from_path_quoted = shell_words::quote(&from_path_quoted);
    let to_path_quoted = to_path.as_ref().to_string_lossy().into_owned();
    let to_path_quoted = shell_words::quote(&to_path_quoted);
    let s = format!("{action} {from_path_quoted} {to_path_quoted}");
    println!("{s}");
    if cp_not_mv {
        std::fs::copy(from_path, to_path).context(s)?;
    } else {
        std::fs::rename(from_path, to_path).context(s)?;
    }
    Ok(())
}

pub(crate) fn fs_rm_file<P: AsRef<Path>>(rm_path: P) -> Result<()> {
    let rm_path_quoted = rm_path.as_ref().to_string_lossy().into_owned();
    let rm_path_quoted = shell_words::quote(&rm_path_quoted);
    let s = format!("rm {rm_path_quoted}");
    println!("{s}");
    std::fs::remove_file(rm_path).context(s)?;
    Ok(())
}
