// Copyright (C) Microsoft Corporation. All rights reserved.

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

mod error;
pub use error::{Error, Result};
use serde::de::IntoDeserializer;

pub(crate) mod imp;
//use crate::imp::sym::Sym;
//use crate::imp::rule::Rule;

pub use crate::imp::hasher::DefaultBuildHasher;

//=================================================================================================|

#[rustfmt::skip]
use std::{
    borrow::Cow,
    cmp::Eq,
    hash::{BuildHasher, Hash, Hasher},
    //os::raw,
    rc::Rc
    //str::FromStr,
    //sync::OnceLock,
};

use bimap::hash::BiHashMap;
//use either::Either;
use hashbrown::HashMap;
use indoc::indoc;
//use rand::{distr::Uniform, Rng, RngCore};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tinyset::setu32::SetU32;
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use util::const_minmax::const_min_u128;

//=================================================================================================|

// The internal representation type for a symbol as a zero-based ordinal.
type SymRepr = u32;

// The internal representation type for set of symbols.
type SymSetRepr = SetU32;

// Type representing the cost of a rule.
type RuleCost = i32;

// Type representing a sum of many rule costs.
type CostSum = i64;

type DynFnRefSymbolToCowstr<Symbol> = dyn Fn(&Symbol) -> Cow<'static, str>;

//=================================================================================================|

/// [`BuildHasher`] for [`Symbol`].
type BuildHasher_Symbol = DefaultBuildHasher;

/// [`BuildHasher`] for [`Sym`].
type BuildHasher_Sym = DefaultBuildHasher;

//=================================================================================================|

pub struct Domain<'f, Symbol>
where
    Symbol: Eq + Hash,
{
    opt_ref_dyn_fn_symbol_to_cowstr: Option<&'f DynFnRefSymbolToCowstr<Symbol>>,

    build_hasher_symbol: BuildHasher_Symbol,
    build_hasher_sym: BuildHasher_Sym,

    symbols: HashMap<Symbol, (), BuildHasher_Symbol>,
    symbol_to_sym: HashMap<Symbol, SymRepr, BuildHasher_Symbol>,
    sym_to_symbol: HashMap<SymRepr, Symbol, BuildHasher_Sym>,
    //bimap: BiHashMap<Symbol, SymRepr>,
    //rules: HashSet<Rule<Symbol>>,
}

impl<'f, Symbol> Domain<'f, Symbol>
where
    Symbol: Eq + Hash,
{
    /// The max number of active symbols in any solving operation.
    ///
    /// Symbols which only appear in rules that have not yet been considered relevant may not
    /// apply to this llmit.
    pub const MAX_ACTIVE_SYMBOLS: usize = const_min_u128(&[
        const_min_u128(&[u128::MAX - 1, SymRepr::MAX as u128]) + 1,
        usize::MAX as u128,
    ]) as usize;

    const MAX_SYMREPR: SymRepr = (Self::MAX_ACTIVE_SYMBOLS as u128 - 1) as SymRepr;

    /// The max number of rules.
    ///
    /// Note that we limit to [`i32::MAX`] here so we can use `i64` for a sum of costs without worrying
    /// about overflow.
    pub const MAX_RULES: usize = const_min_u128(&[i32::MAX as u128, usize::MAX as u128]) as usize;

    /// Creates an empty [`Problem`].
    ///
    /// - `opt_ref_dyn_fn_symbol_to_cowstr` - Function to convert a symbol to a string. Optional.
    pub fn new<H: Hash>(
        opt_ref_dyn_fn_symbol_to_cowstr: Option<&'f DynFnRefSymbolToCowstr<Symbol>>,
        seed: H,
    ) -> Self {
        let [build_hasher_symbol, build_hasher_sym] =
            crate::imp::hasher::BuildHasher_StableSipHasher128::new_arr(seed);

        let symbols = HashMap::with_hasher(build_hasher_symbol.clone());
        let symbol_to_sym = HashMap::with_hasher(build_hasher_symbol.clone());
        let sym_to_symbol = HashMap::with_hasher(build_hasher_sym.clone());

        Domain {
            opt_ref_dyn_fn_symbol_to_cowstr,
            build_hasher_symbol,
            build_hasher_sym,
            symbols,
            symbol_to_sym,
            sym_to_symbol,
            //bimap: BiHashMap::new(),
            //rules: Vec::new(),
        }
    }

    /// Attempts to convert a [`T: TryInto<u32>`](std::convert::TryInto) to a [`SymRepr`].
    pub fn sym_try_from<T>(src: T) -> Option<SymRepr>
    where
        T: TryInto<u32>,
    {
        #[allow(clippy::absurd_extreme_comparisons)]
        <T as TryInto<u32>>::try_into(src)
            .ok()
            .filter(|&sym| sym <= Self::MAX_SYMREPR)
    }
}

/// Calls `f` with the recommended amount to call [`try_reserve`] with.
fn reserve_addl<E, F>(cur: usize, f: F) -> Result<()>
where
    E: Into<Error>,
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

impl<'f, Symbol> Domain<'f, Symbol>
where
    Symbol: Eq + Hash + Clone,
{
    /// Hashes a [`Symbol`].
    pub fn hash_symbol(&self, symbol: &Symbol) -> u64 {
        self.build_hasher_symbol.hash_one(symbol)
    }

    /// Hashes a [`SymRepr`].
    pub fn hash_sym(&self, sym: SymRepr) -> u64 {
        self.build_hasher_sym.hash_one(sym)
    }

    /// Introduces a new symbol [`Symbol`] into the domain independent of any rules.
    ///
    /// Returns:
    ///
    /// - `Ok(true)` iff it is a new symbol to this domain
    /// - `Ok(false)` if this symbol had been introduced previously.
    /// - `Err(Error::SymbolSetFull)` if the symbol set is full.
    pub fn symbol(&mut self, symbol: &Symbol) -> Result<bool> {
        let (is_new, _) = self.ensure_symbol(symbol)?;
        Ok(is_new)
    }

    /// Ensures `self.symbols` contains the `Symbol`. Returns a [`bool`] indicating newly inserted
    /// and the [`symbol`]'s hash value.
    fn ensure_symbol(&mut self, symbol: &Symbol) -> Result<(bool, u64)> {
        // Ensure we have some additional capacity in advance, whether we need it or not.
        reserve_addl(self.symbols.capacity(), |addl| {
            self.symbols.try_reserve(addl)
        })?;

        let symbol_hash_u64 = self.hash_symbol(symbol);

        let is_match = |other: &Symbol| *symbol == *other;

        let symbols_raw_entry_mut = self
            .symbols
            .raw_entry_mut()
            .from_hash(symbol_hash_u64, |other: &Symbol| *symbol == *other);

        // self is mutably borrowed for this scope
        use hashbrown::hash_map::{RawEntryBuilderMut, RawEntryMut};
        let symbols_raw_entry_mut = self
            .symbols
            .raw_entry_mut()
            .from_hash(symbol_hash_u64, is_match);

        use hashbrown::hash_map::RawEntryMut::*;
        let is_new = match symbols_raw_entry_mut {
            Occupied(entry) => false,
            Vacant(entry) => {
                entry.insert_hashed_nocheck(symbol_hash_u64, symbol.clone(), ());
                true
            }
        };

        Ok((is_new, symbol_hash_u64))
    }

    /// Gets the [`SymRepr`] for a [`Symbol`], or assigns a new one if it does not exist.
    ///
    /// You probably don't want to call this. Let the system manage the creation of syms.
    pub fn get_or_assign_sym_repr(&mut self, symbol: &Symbol) -> Result<SymRepr> {
        use hashbrown::hash_map::{
            RawEntryBuilderMut,
            RawEntryMut::{self, *},
        };

        // insert into symbols
        let (_, symbol_hash_u64) = self.ensure_symbol(symbol)?;

        // Ensure we have some additional capacity in advance, whether we need it or not.
        reserve_addl(self.symbol_to_sym.capacity(), |addl| {
            self.symbol_to_sym.try_reserve(addl)
        })?;
        reserve_addl(self.sym_to_symbol.capacity(), |addl| {
            self.sym_to_symbol.try_reserve(addl)
        })?;

        // Insert or lookup into `symbol_to_sym`.
        let (is_new_sym, sym) = {
            let is_symbol_match = |other: &Symbol| *symbol == *other;

            // Copy these in advance because `self.symbol_to_sym.raw_entry_mut()` below borrows self mutably.
            let symbol_to_sym_len = self.symbol_to_sym.len();
            let opt_ref_dyn_fn_symbol_to_cowstr = self.opt_ref_dyn_fn_symbol_to_cowstr;

            let symbol_to_sym_raw_entry_mut = self
                .symbol_to_sym
                .raw_entry_mut()
                .from_hash(symbol_hash_u64, is_symbol_match);

            match symbol_to_sym_raw_entry_mut {
                Occupied(entry) => (false, *entry.get()),
                Vacant(entry) => {
                    // pick the next sym value
                    let Some(sym) = Self::sym_try_from(symbol_to_sym_len) else {
                        let opt_symbol_str = self.try_symbol_to_str(symbol);
                        return Err(Error::SymbolSetFull {
                            opt_symbol_str,
                            current_number: self.symbols.len(),
                        });
                    };

                    entry.insert_hashed_nocheck(symbol_hash_u64, symbol.clone(), sym);

                    (true, sym)
                }
            }
        };

        // Insert into `sym_to_symbol`.
        if is_new_sym {
            let sym_hash_u64 = self.hash_sym(sym);

            let is_sym_match = |other: &SymRepr| sym == *other;

            let sym_to_symbol_raw_entry_mut = self
                .sym_to_symbol
                .raw_entry_mut()
                .from_hash(sym_hash_u64, is_sym_match);

            match sym_to_symbol_raw_entry_mut {
                Occupied(entry) => {
                    debug_assert!(entry.get() == symbol);
                }
                Vacant(entry) => {
                    entry.insert_hashed_nocheck(sym_hash_u64, sym, symbol.clone());
                }
            }
        } else {
            debug_assert!(self.sym_to_symbol.contains_key(&sym));
        }

        Ok(sym)
    }

    /// Adds a new rule to the domain.
    pub fn add_rule<I, J>(&mut self, requires: I, produces: J, cost: i32) -> bool
    where
        I: IntoIterator<Item = Symbol>,
        J: IntoIterator<Item = Symbol>,
    {
        /*
        let mut requ = SymbolSetRepr::new();
        for symbol in requires {
            requ.insert(self.get_or_insert(symbol));
        }

        let mut prod = SymbolSetRepr::new();
        for symbol in requires {
            prod.insert(self.get_or_insert(symbol));
        }
        // */
        false //?
    }

    /// Attempts to convert a `Symbol` to a string.
    pub fn try_symbol_to_str(&self, symbol: &Symbol) -> Option<Cow<'static, str>> {
        self.opt_ref_dyn_fn_symbol_to_cowstr
            .map(|fn_symbol_to_cow_str| fn_symbol_to_cow_str(symbol))
    }
}

impl<Symbol> std::fmt::Debug for Domain<'_, Symbol>
where
    Symbol: Eq + Hash + std::fmt::Debug,
{
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            indoc! {"
            Domain {{
                symbols: {{"}
        )?;

        for symbol in self.symbols.keys() {
            writeln!(f, "        {symbol:?},")?;
        }

        writeln!(f, "    }},\n    symbol_to_sym: {{")?;

        for (symbol, sym) in self.symbol_to_sym.iter() {
            writeln!(f, "        {symbol:?} -> {sym:?},")?;
        }

        writeln!(f, "    }},\n    sym_to_symbol: {{")?;

        for (sym, symbol) in self.sym_to_symbol.iter() {
            writeln!(f, "        {sym:?} -> {symbol:?},")?;
        }

        writeln!(f, "    }},\n    rules: [")?;

        /*
        for (ix, r) in self.rules.iter().enumerate() {
            writeln!(f, "        {ix:4}: {r:?},")?;
        }
        // */

        write!(f, "    ],\n}}")
    }
}

impl<Symbol> std::fmt::Display for Domain<'_, Symbol>
where
    Symbol: Eq + Hash + std::fmt::Debug,
    //Self: std::fmt::Debug,
{
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl<Symbol> serde::Serialize for Domain<'_, Symbol>
where
    Symbol: Eq + Hash + serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Domain", 1)?;
        //? state.serialize_field("rules", &self.rules)?;
        state.end()
    }
}

//=================================================================================================|

//, serde::Deserialize, serde::Serialize

#[derive(Clone, Debug, serde::Serialize)]
pub struct Rule_Symbol<Symbol>
where
    Symbol: Eq + Hash + serde::Serialize,
{
    id: usize,
    requires: HashMap<Symbol, (), BuildHasher_Symbol>,
    produces: HashMap<Symbol, (), BuildHasher_Symbol>,
    cost: RuleCost,
}

//=================================================================================================|

#[derive(Clone, Debug, PartialEq, Eq //, Hash
)]
pub struct Rule_Sym {
    id: usize,
    requires: HashMap<SymRepr, (), BuildHasher_Sym>,
    produces: HashMap<SymRepr, (), BuildHasher_Sym>,
    cost: RuleCost,
}
/*
impl Rule {
    pub fn new<I, J, Symbol>(requires: I, produces: J, cost: i32) -> Result<Rule>
    where
        I: IntoIterator<Item = Symbol>,
        J: IntoIterator<Item = Symbol>,
    {
        let self_ = Rule {
            requires: requires.parse()?,
            produces: produces.parse()?,
            cost,
        };
        Ok(self_)
    }
}
pub struct RuleKey<Symbol>
where
    Symbol: Eq + Hash,
{
    SetU32,
}
#[derive(Clone//, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash
)]
pub struct Rules {
    rules: HashMap<RuleKey, RuleValue>,
}
//
*/

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use super::{Domain, DynFnRefSymbolToCowstr, SymRepr};
    use anyhow::{anyhow, bail, ensure, Context, Result};
    use insta::{assert_debug_snapshot, assert_snapshot};
    use static_assertions::assert_impl_all;

    #[test]
    fn t0() {
        type Symbol = char;
        assert_impl_all!(Symbol: Eq, Hash);

        fn symbol_to_cowstr(ch: &char) -> Cow<'static, str> {
            ch.to_string().into()
        }
        let opt_ref_dyn_fn_symbol_to_cowstr: Option<&DynFnRefSymbolToCowstr<Symbol>> =
            Some(&symbol_to_cowstr);
        let seed = 1234;
        let mut domain = Domain::<char>::new(opt_ref_dyn_fn_symbol_to_cowstr, seed);

        // `snapshots/formulator__t__t0.snap`
        assert_snapshot!(domain);

        domain.symbol(&'a').unwrap();

        // `snapshots/formulator__t__t0-2.snap`
        assert_snapshot!(domain);

        let sym = domain.get_or_assign_sym_repr(&'a').unwrap();

        // `snapshots/formulator__t__t0-3.snap`
        assert_debug_snapshot!((domain, sym));
    }
}
