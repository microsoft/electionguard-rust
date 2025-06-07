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

//=================================================================================================|

pub(crate) mod domain;
pub(crate) mod hasher;
pub(crate) mod problem;
pub(crate) mod rule;
pub(crate) mod solution;
//pub(crate) mod sym;
//pub(crate) mod sym_set;

//=================================================================================================|

#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    borrow::Cow,
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    hash::{BuildHasher, Hash, Hasher},
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
//use log::{debug, error, info, trace, warn};
//use rand::{distr::Uniform, Rng, RngCore};
use tinyset::setu32::SetU32;

use util::const_minmax::const_min_u128;

//=================================================================================================|

// The internal representation type for a symbol as a zero-based ordinal.
type SymRepr = u32;

/// The max value of a SymRepr
pub(crate) static MAX_SYMREPR: SymRepr =
    const_min_u128(&[usize::MAX as u128 - 1, SymRepr::MAX as u128]) as SymRepr;

// The internal representation type for set of symbols.
type SymSetRepr = SetU32;

//=================================================================================================|

/// [`BuildHasher`] for [`Symbol`].
pub(crate) type BuildHasher_Symbol = crate::DefaultBuildHasher;

/// [`BuildHasher`] for [`Sym`].
pub(crate) type BuildHasher_Sym = crate::DefaultBuildHasher;

//=================================================================================================|

/// Calls `f` with the recommended amount to call [`try_reserve`] with.
pub(crate) fn reserve_addl<E, F>(cur: usize, f: F) -> crate::error::Result<()>
where
    E: Into<crate::error::Error>,
    F: FnOnce(usize) -> std::result::Result<(), E>,
{
    const CAPACITY_MULTIPLE: usize = 64;
    let wanted = (cur + 1).next_multiple_of(CAPACITY_MULTIPLE);
    let addl = wanted - cur;
    if 0 < addl {
        f(addl).map_err(Into::into)
    } else {
        Ok(())
    }
}

//=================================================================================================|

pub(crate) fn gen_random_name_strings<R: rand_core::RngCore>(
    cnt: usize,
    rng: &mut R,
) -> Vec<String> {
    use hashbrown::HashMap;
    use rand_distr::{Distribution, Exp, Uniform};

    type Symbol = String;

    fn symbol_to_cowstr(symbol: &Symbol) -> Cow<'static, str> {
        Cow::Owned(symbol.clone())
    }

    let opt_bx_dyn_fn_symbol_to_cowstr: Option<&crate::DynFnRefSymbolToCowstr<Symbol>> =
        Some(&symbol_to_cowstr);

    let exp = Exp::new(0.5).unwrap();

    // Unwrap() is justified here because this is a const input.
    #[allow(clippy::unwrap_used)]
    let distr_char = Uniform::try_from('a'..='z').unwrap();

    let hash_builder = crate::DefaultBuildHasher::new(rng.next_u64());

    let mut h: HashMap<String, (), _> = HashMap::with_capacity_and_hasher(cnt * 2, hash_builder);
    let mut v = vec![];
    let mut cnt_iter = 25_u32;
    while v.len() < cnt && cnt_iter < (1u32 << 30) {
        cnt_iter += 1;
        debug_assert_ne!(cnt_iter, 1u32 << 30);

        let exp_multiplier: f64 = (cnt_iter as f64).log(26.0);
        let f: f64 = exp.sample(rng) * exp_multiplier;
        let string_len = 1_usize + f.round() as usize;

        let mut s = String::new();
        while s.len() < string_len {
            let ch = distr_char.sample(rng);
            s.push(ch);
        }

        if h.insert(s.clone(), ()).is_none() {
            v.push(s);
        }
    }

    v
}
