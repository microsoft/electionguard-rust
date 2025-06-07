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
//use equivalent::Equivalent;
use hashbrown::HashMap;
use indoc::indoc;
//use indexmap::set::IndexSet;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::{Error, Result},
    imp::{BuildHasher_Sym, BuildHasher_Symbol, MAX_SYMREPR, SymRepr, SymSetRepr, reserve_addl},
    //Problem, Rule, RuleCost, RuleCostSum, RULE_IX_INVALID,
};

use util::const_minmax::const_min_u128;

//=================================================================================================|

/// Type of a fn that can convert a symbol to a [`string or str`](std::borrow::Cow).
pub type DynFnRefSymbolToCowstr<Symbol> = dyn Fn(&Symbol) -> Cow<'static, str>;

/// Type of a Box of fn that can convert a symbol to a [`string or str`](std::borrow::Cow).
pub type BoxDynFnRefSymbolToCowstr<Symbol> = Box<DynFnRefSymbolToCowstr<Symbol>>;

/// Type of an option of Box of fn that can convert a symbol to a [`string or str`](std::borrow::Cow).
pub type OptionBoxDynFnRefSymbolToCowstr<Symbol> = Option<BoxDynFnRefSymbolToCowstr<Symbol>>;

//=================================================================================================|

pub struct Domain<Symbol>
where
    Symbol: Eq + Hash,
{
    opt_bx_dyn_fn_symbol_to_cowstr: OptionBoxDynFnRefSymbolToCowstr<Symbol>,

    symbols: HashMap<Symbol, usize, BuildHasher_Symbol>,
    /*
    refcell_symbols: RefCell<IndexSet<Symbol, BuildHasher_Symbol>>,
    // */
}

impl<Symbol> Domain<Symbol>
where
    Symbol: Eq + Hash,
{
    /// The max number of active symbols in any solving operation.
    ///
    /// Symbols which only appear in rules that have not yet been considered relevant may not
    /// apply to this limit.
    pub const MAX_ACTIVE_SYMBOLS: usize = const_min_u128(&[
        const_min_u128(&[u128::MAX - 1, MAX_SYMREPR as u128]) + 1,
        usize::MAX as u128,
    ]) as usize;

    /// Creates a new, empty [`Domain`].
    ///
    /// - `opt_bx_dyn_fn_symbol_to_cowstr` - Function to convert a symbol to a string. Optional.
    /// - `seed` - Seed data with which to initialize data structure hash function.
    pub fn new<H: Hash>(
        opt_bx_dyn_fn_symbol_to_cowstr: OptionBoxDynFnRefSymbolToCowstr<Symbol>,
        seed: H,
    ) -> Self {
        let [build_hasher_symbol] =
            crate::imp::hasher::BuildHasher_StableSipHasher128::new_arr(seed);

        /*
        let symbols = IndexSet::with_hasher(build_hasher_symbol);

        let refcell_symbols = RefCell::new(symbols);

        Domain {
            opt_bx_dyn_fn_symbol_to_cowstr,
            refcell_symbols,
        }
        // */
        let symbols = HashMap::with_hasher(build_hasher_symbol.clone());

        Domain {
            opt_bx_dyn_fn_symbol_to_cowstr,
            symbols,
        }
    }

    /// Returns access to the [`BuildHasher`](std::hash::BuildHasher) used for hashing [`Symbol`]s.
    pub fn build_hasher_symbol(&self) -> &BuildHasher_Symbol {
        self.symbols.hasher()
    }

    /// Hashes a [`Symbol`].
    pub fn hash_symbol(&self, symbol: &Symbol) -> u64 {
        self.build_hasher_symbol().hash_one(symbol)
    }

    /*
    /// Returns the total number of [`Symbol`]s in this [`Domain`].
    pub fn cnt_symbols(&self) -> usize {
        let opt_symbols = self.refcell_symbols.try_borrow().ok();

        // Unwrap() is justified here because we are careful to scope borrows.
        #[allow(clippy::unwrap_used)]
        let symbols = opt_symbols.unwrap();

        symbols.len()
    }
    // */
}

impl<Symbol> Domain<Symbol>
where
    Symbol: Eq + Hash + Clone,
{
    /// Introduces a new [`Symbol`] into this [`Domain`] independent of any rules.
    ///
    /// Returns a reference to the symbol with lifetime of this [`Domain`]:
    ///
    /// - `Ok((true, symbol))` iff it is a new symbol to this domain
    /// - `Ok((false, symbol))` if this symbol had been introduced previously.
    /// - `Err(Error::SymbolSetFull)` if the symbol set is full.
    pub fn symbol<'d, 'a>(&'d mut self, symbol: &'a Symbol) -> Result<(bool, &'d Symbol)> {
        let (is_new, ref_d_symbol, _) = self.ensure_symbol(symbol)?;
        Ok((is_new, ref_d_symbol))
    }

    /// Ensures `self.symbols` contains the `Symbol`. Returns a [`bool`] indicating newly inserted
    /// and the [`symbol`]'s hash value.
    pub(crate) fn ensure_symbol<'d, 's>(
        &'d mut self,
        symbol: &'s Symbol,
    ) -> Result<(bool, &'d Symbol, u64)> {
        // Ensure we have some additional capacity in advance, whether we need it or not.
        reserve_addl(self.symbols.capacity(), |addl| {
            self.symbols.try_reserve(addl)
        })?;

        let symbol_hash_u64 = self.hash_symbol(symbol);

        let is_match = |other: &Symbol| *symbol == *other;

        // Copy these in advance because `self.symbol_to_sym.raw_entry_mut()` below borrows self mutably.
        let symbols_len = self.symbols.len();
        let opt_bx_dyn_fn_symbol_to_cowstr = self
            .opt_bx_dyn_fn_symbol_to_cowstr
            .as_ref()
            .map(|bx| bx.as_ref());

        // self is mutably borrowed for this scope
        use hashbrown::hash_map::{RawEntryBuilderMut, RawEntryMut};
        let symbols_raw_entry_mut = self
            .symbols
            .raw_entry_mut()
            .from_hash(symbol_hash_u64, is_match);

        use hashbrown::hash_map::RawEntryMut::*;
        let (is_new, ref_d_symbol): (bool, &'d Symbol) = match symbols_raw_entry_mut {
            Occupied(entry) => (false, entry.into_key()),
            Vacant(entry) => {
                if Self::MAX_ACTIVE_SYMBOLS <= symbols_len {
                    let opt_symbol_str = opt_bx_dyn_fn_symbol_to_cowstr
                        .map(|fn_symbol_to_cow_str| fn_symbol_to_cow_str(symbol));
                    let e = Error::SymbolSetFull {
                        opt_symbol_str,
                        current_number: symbols_len,
                    };
                    return Err(e);
                } else {
                    let symbol_ix = symbols_len;
                    let (ref_d_symbol, _) =
                        entry.insert_hashed_nocheck(symbol_hash_u64, symbol.clone(), symbol_ix);
                    (true, ref_d_symbol)
                }
            }
        };

        Ok((is_new, ref_d_symbol, symbol_hash_u64))
    }

    /*
    /// Introduces a new [`Symbol`] into this [`Domain`] independent of any rules.
    ///
    /// This version is to be preferred when you have a `&mut self`.
    ///
    /// Returns :
    ///
    /// - `Ok((symbol, index))` with a reference to the symbol with lifetime of this [`Domain`]
    /// - `Err(Error::SymbolSetFull)` if the symbol needs to be added but the set is already full.
    pub fn symbol_mut<'d, 'a>(&'d mut self, symbol: &'a Symbol) -> Result<(usize, &'d Symbol)> {
        let ref_d_symbols = self.refcell_symbols.get_mut();

        Self::symbol_(&self.opt_bx_dyn_fn_symbol_to_cowstr, ref_d_symbols, symbol)
    }

    /// Introduces a new [`Symbol`] into this [`Domain`] independent of any rules.
    ///
    /// This version is for when you only have a `&self`, but it could theoretically fail
    /// if somehow there is already mutable ref.
    ///
    /// Returns :
    ///
    /// - `Ok((symbol, index))` with a reference to the symbol with lifetime of this [`Domain`]
    /// - `Err(Error::SymbolsAlreadyMutablyInUse)` if there is already a mutable ref out.
    /// - `Err(Error::SymbolSetFull)` if the Symbol needs to be added but the set is already full.
    pub fn symbol<'d, 'a>(&'d self, symbol: &'a Symbol) -> Result<(usize, &'d Symbol)> {
        let ref_d_symbols: std::cell::Ref<'d, _> = self.refcell_symbols.try_borrow()
                .or(Err(Error::SymbolsAlreadyMutablyInUse))?;

        if let Some((index, ref_d_symbol)) = ref_d_symbols.get_full(symbol) {
            // Symbol already exists in set
            //drop(ref_d_symbols);
            Ok((index, ref_d_symbol))
        } else {
            // Symbol must be added to set
            drop(ref_d_symbols);

            let stdcellrefmut_d_symbols: std::cell::RefMut<'d, _> = self.refcell_symbols.try_borrow_mut()
                .or(Err(Error::SymbolsAlreadyInUse))?;

            Self::symbol_(&self.opt_bx_dyn_fn_symbol_to_cowstr, stdcellrefmut_d_symbols, symbol)
        }
    }

    fn symbol_<'d, 'a, M, S>(
        opt_bx_dyn_fn_symbol_to_cowstr: &OptionBoxDynFnRefSymbolToCowstr<Symbol>,
        std_cell_refmut_symbols: M, //std::cell::RefMut<'d, IndexSet<Symbol, S>>,
        ref_a_symbol: &'a Symbol
    ) -> Result<(usize, &'d Symbol)>
    where
        M: std::ops::Deref<Target = IndexSet<Symbol, S>> + std::ops::DerefMut,
        S: BuildHasher,
    {
        // Ensure we have some additional capacity in advance, whether we need it or not.
        reserve_addl(std_cell_refmut_symbols.capacity(), |addl| {
            std_cell_refmut_symbols.try_reserve(addl)
            .map_err(|_| Error::AllocationFailed)
        })?;

        let (index, newly_added) = std_cell_refmut_symbols.insert_full(ref_a_symbol.clone());

        // Unwrap() is justified here because we just got this index from insertion.
        #[allow(clippy::unwrap_used)]
        let ref_d_symbol = std_cell_refmut_symbols.get_index(index).unwrap();

        Ok((index, ref_d_symbol))

        /*
        let symbol_hash_u64 = self.hash_symbol(symbol);

        let is_match = |other: &Symbol| *symbol == *other;

        // Copy these in advance because `self.symbol_to_sym.raw_entry_mut()` below borrows self mutably.
        let symbols_len = symbols.len();
        let opt_bx_dyn_fn_symbol_to_cowstr = self
            .opt_bx_dyn_fn_symbol_to_cowstr
            .as_ref()
            .map(|bx| bx.as_ref());

        // self is mutably borrowed for this scope
        use hashbrown::hash_map::{RawEntryBuilderMut, RawEntryMut};
        let symbols_raw_entry_mut = self
            .symbols
            .raw_entry_mut()
            .from_hash(symbol_hash_u64, is_match);

        use hashbrown::hash_map::RawEntryMut::*;
        let (is_new, ref_d_symbol): (bool, &'d Symbol) = match symbols_raw_entry_mut {
            Occupied(entry) => (false, entry.into_key()),
            Vacant(entry) => {
                if Self::MAX_ACTIVE_SYMBOLS <= symbols_len {
                    let opt_symbol_str = opt_bx_dyn_fn_symbol_to_cowstr
                        .map(|fn_symbol_to_cow_str| fn_symbol_to_cow_str(symbol));
                    let e = Error::SymbolSetFull {
                        opt_symbol_str,
                        current_number: symbols_len,
                    };
                    return Err(e);
                } else {
                    let symbol_ix = symbols_len;
                    let (ref_d_symbol, _) =
                        entry.insert_hashed_nocheck(symbol_hash_u64, symbol.clone(), symbol_ix);
                    (true, ref_d_symbol)
                }
            }
        };

        Ok((is_new, ref_d_symbol, symbol_hash_u64))
        // */
    }
    // */
}

impl<Symbol> Domain<Symbol>
where
    Symbol: Eq + Hash,
{
    /// Obtains a &'d lifetime ref given an arbitrary `Symbol` ref.
    /// Also returns the symbol's hash value.
    ///
    /// Returns `None` if the `Symbol` does not exist in the domain.
    pub(crate) fn get_existing_symbol_hashvalue<'d, 's>(
        &'d self,
        symbol: &'s Symbol,
    ) -> (Option<&'d Symbol>, u64) {
        let (opt_pr_symbol_index, symbol_hash_u64) =
            self.get_existing_symbol_index_hashvalue(symbol);

        let opt_symbol = opt_pr_symbol_index.map(|pr_symbol_index| pr_symbol_index.0);

        (opt_symbol, symbol_hash_u64)
    }

    /// Obtains a &'d lifetime ref given an arbitrary `Symbol` ref.
    /// Also returns the symbol's hash value and index.
    ///
    /// Returns `None` if the `Symbol` does not exist in the domain.
    pub(crate) fn get_existing_symbol_index_hashvalue<'d, 's>(
        &'d self,
        symbol: &'s Symbol,
    ) -> (Option<(&'d Symbol, usize)>, u64) {
        let symbol_hash_u64 = self.hash_symbol(symbol);

        let is_match = |other: &Symbol| *symbol == *other;

        let opt_pr_symbol_index: Option<(&'d Symbol, usize)> = self
            .symbols
            .raw_entry()
            .from_hash(symbol_hash_u64, is_match)
            .map(|pr| (pr.0, *pr.1));

        (opt_pr_symbol_index, symbol_hash_u64)
    }

    /// Obtains a &'d lifetime ref given an arbitrary `Symbol` ref.
    ///
    /// Returns `None` if the `Symbol` does not exist in the domain.
    pub(crate) fn get_existing_symbol<'d, 's>(&'d self, symbol: &'s Symbol) -> Option<&'d Symbol> {
        self.get_existing_symbol_hashvalue(symbol).0
    }

    /// Returns the 0-based index value for a known symbol.
    ///
    /// Returns `None` if the `Symbol` does not exist in the domain.
    pub fn get_existing_index(&self, symbol: &Symbol) -> Option<usize> {
        let (opt_pr_symbol_index, _) = self.get_existing_symbol_index_hashvalue(symbol);
        opt_pr_symbol_index.map(|pr| pr.1)
    }

    /// Attempts to convert a `Symbol` to a string.
    ///
    /// Returns `None` if the `Symbol` does not exist in the domain.
    pub fn try_symbol_to_str(&self, symbol: &Symbol) -> Option<Cow<'static, str>> {
        self.opt_bx_dyn_fn_symbol_to_cowstr
            .as_ref()
            .map(|bx_fn_symbol_to_cow_str| bx_fn_symbol_to_cow_str(symbol))
    }

    /// Attempts to convert a [`Symbol`] to a string.
    ///
    /// If it cannot be converted to a string, a string representation of its index value,
    /// prefixed with '@', is substituted.
    ///
    /// Returns `None` if the `Symbol` does not exist in the domain.
    pub fn get_existing_symbol_string(&self, symbol: &Symbol) -> Option<Cow<'static, str>> {
        self.try_symbol_to_str(symbol).or_else(|| {
            let opt_symbol_ix = self.get_existing_index(symbol);
            opt_symbol_ix.map(|symbol_ix| format!("@{symbol_ix}").into())
        })
    }
}

impl<Symbol> Domain<Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    /// Returns a sorted collection of the Symbols
    pub fn sorted_symbols(&self) -> Vec<&Symbol> {
        let mut symbols: Vec<&Symbol> = self.symbols.keys().collect();
        symbols.sort();
        symbols
    }

    /// Returns a sorted collection of the [`Symbol`]s as strings.
    /// When the `Symbol` cannot be converted to a string, its index
    /// value is substituted.
    pub fn sorted_symbols_as_strings(&self) -> Vec<Cow<'static, str>> {
        self.sorted_symbols()
            .iter()
            .map(|&symbol| {
                if let Some(cowstr) = self.try_symbol_to_str(symbol) {
                    cowstr
                } else {
                    // Unwrap() is justified here because we are iterating only known existing symbols.
                    #[allow(clippy::unwrap_used)]
                    self.get_existing_symbol_string(symbol).unwrap()
                }
            })
            .collect()
    }
}

impl<Symbol> std::fmt::Debug for Domain<Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_domain(f)
    }
}

impl<Symbol> std::fmt::Display for Domain<Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_domain(f)
    }
}

impl<Symbol> Domain<Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    fn fmt_domain(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.symbols.is_empty() {
            write!(f, "Domain {{ }}")
        } else {
            let symbols = self.sorted_symbols();

            let strs: Vec<Cow<'static, str>> = self.sorted_symbols_as_strings();

            writeln!(f, "Domain {{")?;

            let line_prefix: &str = "    ";
            let line_len_max: usize = 72;
            fmt_strs_comma_line(f, strs.as_slice(), line_prefix, line_len_max)?;

            write!(f, "}}")
        }
    }
}

fn fmt_strs_comma_line<S: AsRef<str>>(
    f: &mut std::fmt::Formatter<'_>,
    strs: &[S],
    line_prefix: &str,
    line_len_max: usize,
) -> std::fmt::Result {
    let line_prefix_len = line_prefix.len();

    let mut line_len = 0;
    for s in strs {
        if line_len == 0 {
            write!(f, "{}", line_prefix)?;
            line_len = line_prefix_len;
        }

        let s: &str = s.as_ref();
        let s_len = s.len();
        if line_len <= line_prefix_len {
            write!(f, "{s}")?;
            line_len += s_len;
        } else {
            let line_len_if_s_appended = line_len + 2 + s_len;
            if line_len_if_s_appended < line_len_max {
                write!(f, ", {s}")?;
                line_len = line_len_if_s_appended;
            } else {
                write!(f, ",\n{line_prefix}{s}")?;
                line_len = line_prefix_len + s_len;
            }
        }
    }

    if line_len != 0 {
        writeln!(f)?;
    }
    Ok(())
}

//-------------------------------------------------------------------------------------------------|

impl<Symbol> serde::Serialize for Domain<Symbol>
where
    Symbol: Eq + Hash + Ord + serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Domain", 1)?;

        let mut symbols: Vec<&Symbol> = self.symbols.keys().collect();
        symbols.sort();
        state.serialize_field("symbols", &symbols)?;
        state.end()
    }
}

//=================================================================================================|

/// Generates a random [`Domain`] having the [`String`] symbol type.
pub fn gen_random_domain<R: rand_core::RngCore>(
    cnt_symbols: usize,
    rng: &mut R,
) -> Result<crate::Domain<String>> {
    use static_assertions::assert_impl_all;
    type Symbol = String;

    fn symbol_to_cowstr(symbol: &Symbol) -> Cow<'static, str> {
        Cow::Owned(symbol.clone())
    }
    assert_impl_all!(Symbol: Eq, Hash);

    let opt_bx_dyn_fn_symbol_to_cowstr: OptionBoxDynFnRefSymbolToCowstr<Symbol> =
        Some(Box::new(symbol_to_cowstr));

    let mut domain = crate::Domain::<Symbol>::new(opt_bx_dyn_fn_symbol_to_cowstr, rng.next_u64());

    let v_names = crate::imp::gen_random_name_strings(cnt_symbols, rng);
    for symbol in v_names {
        domain.symbol(&symbol)?;
    }

    Ok(domain)
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use super::{Domain, DynFnRefSymbolToCowstr, SymRepr};
    use anyhow::{Context, Result, anyhow, bail, ensure};
    use insta::{assert_debug_snapshot, assert_json_snapshot, assert_snapshot};
    use static_assertions::assert_impl_all;

    #[test]
    fn t0() {
        type Symbol = char;
        assert_impl_all!(Symbol: Eq, Hash);

        fn symbol_to_cowstr(ch: &char) -> Cow<'static, str> {
            ch.to_string().into()
        }
        let opt_bx_dyn_fn_symbol_to_cowstr: OptionBoxDynFnRefSymbolToCowstr<Symbol> =
            Some(Box::new(symbol_to_cowstr));

        let seed = 1234;
        let mut domain = Domain::<char>::new(opt_bx_dyn_fn_symbol_to_cowstr, seed);

        // `snapshots/formulator__t__t0.snap`
        assert_snapshot!(domain);

        domain.symbol(&'a').unwrap();

        // `snapshots/formulator__t__t0-2.snap`
        assert_snapshot!(domain);

        let (opt_symbol, symbol_hash_u64) = domain.get_existing_symbol_hashvalue(&'a');
        let symbol = opt_symbol.unwrap();

        // `snapshots/formulator__t__t0-3.snap`
        assert_snapshot!(format!(
            "domain: {domain},\nsymbol: {symbol},\nsymbol_hash_u64: {symbol_hash_u64:#018x}"
        ));
    }

    #[test]
    fn t1() {
        use rand_core::{RngCore, SeedableRng};
        use rand_xorshift::XorShiftRng;

        let mut rng = XorShiftRng::seed_from_u64(1234);
        let rng = &mut rng;

        const CNT_SYMBOLS: usize = 50;

        let domain = gen_random_domain(CNT_SYMBOLS, rng).unwrap();

        // `snapshots/formulator__t__t1.snap`
        assert_snapshot!(domain);

        // `snapshots/formulator__t__t1-2.snap`
        assert_json_snapshot!(domain);
    }
}
