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
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
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

use std::{
    borrow::Cow,
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    //iter::zip,
    //marker::PhantomData,
    //path::{Path, PathBuf},
    //sync::Arc,
    //str::FromStr,
    //sync::OnceLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

//use crate::{};

//=================================================================================================|

/// [`Result::Err`](std::result::Result) type of a data resource production operation.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[allow(non_camel_case_types)]
pub enum Error {
    #[error("Parsing Sym")]
    ParseSym,

    #[error("Parsing SymSet")]
    ParseSymSet,

    #[error("UsizeToSymRepr")]
    UsizeToSymRepr,

    #[error("UsizeToSymRepr")]
    SymTryFrom,

    #[error("New symbol{s} could not be added because the domain symbol set is full. \
        It already contains {current_number} symbols.",
        s = opt_symbol_to_space_quoted_string(opt_symbol_str))]
    SymbolSetFull {
        opt_symbol_str: Option<Cow<'static, str>>,
        current_number: usize,
    },

    #[error("Capacity exceeded")]
    CapacityOverflow,

    #[error(
        "New rule could not be added because the rule set is full. It already contains {current_number} rules."
    )]
    RuleSetFull { current_number: usize },

    #[error("Allocation failed")]
    AllocationFailed,
    /*
    #[error("The symbols collection is already in use.")]
    SymbolsAlreadyInUse,

    #[error("The symbols collection is already (mutably) in use.")]
    SymbolsAlreadyMutablyInUse,
    // */
}

/// [`Result`](std::result::Result) type with an [`ProblemError`].
pub type Result<T> = std::result::Result<T, Error>;

impl From<hashbrown::TryReserveError> for Error {
    /// An [`Error`] can always be made from a [`hashbrown::TryReserveError`].
    #[inline]
    fn from(src: hashbrown::TryReserveError) -> Self {
        use hashbrown::TryReserveError::*;
        match src {
            CapacityOverflow => Error::CapacityOverflow,
            _ => Error::AllocationFailed,
        }
    }
}

fn opt_symbol_to_space_quoted_string(opt_symbol: &Option<Cow<'static, str>>) -> Cow<'static, str> {
    match opt_symbol {
        Some(symbol) => format!(" `{}`", symbol).into(),
        None => "".into(),
    }
}
