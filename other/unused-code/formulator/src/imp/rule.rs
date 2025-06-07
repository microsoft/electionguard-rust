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
#![allow(clippy::absurd_extreme_comparisons)] //? TODO: Remove temp development code
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
    //borrow::Cow,
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    hash::{BuildHasher, Hash, Hasher},
    iter::FusedIterator,
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
use hashbrown::HashMap;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use util::const_minmax::const_min_u128;

use crate::{
    Domain, DynFnRefSymbolToCowstr, Problem,
    error::{Error, Result},
    imp::{BuildHasher_Sym, BuildHasher_Symbol, MAX_SYMREPR, SymRepr, SymSetRepr, reserve_addl},
};

//=================================================================================================|

/// Type representing the cost of a rule.
pub type RuleCost = i32;
/*
pub const fn rule_cost_invalid_value() -> RuleCost { RuleCost::MIN }

pub const fn rule_cost_valid_min() -> RuleCost { rule_cost_invalid_value() + 1 }

pub const fn rule_cost_valid_max() -> RuleCost { RuleCost::MAX }

pub const fn valid_rule_cost_range() -> std::ops::RangeInclusive<RuleCost> {
    rule_cost_valid_min() ..= rule_cost_valid_max()
}

pub const fn rule_cost_is_valid(rule_cost: RuleCost) -> bool {
    rule_cost != rule_cost_invalid_value()
}
// */

/// Type representing a sum of many rule costs.
pub type RuleCostSum = i64;

/// The maximum number of rules.
///
/// Note that we limit to [`i32::MAX`] here so we can use `i64` for a sum of costs without worrying
/// about overflow.
pub const RULES_CNT_MAX: usize = const_min_u128(&[i32::MAX as u128, usize::MAX as u128]) as usize;

/// The largest possible rule index.
pub const RULE_IX_MAX: usize = RULES_CNT_MAX - 1;

/// An invalid rule index.
pub const RULE_IX_INVALID: usize = RULES_CNT_MAX;

//=================================================================================================|

/// A rule in the domain.
#[derive(Clone)]
pub struct Rule<'d, Symbol>
where
    Symbol: Eq + Hash,
{
    pub(crate) domain: &'d Domain<Symbol>,
    pub(crate) ix: usize,
    pub(crate) requires: HashMap<&'d Symbol, (), BuildHasher_Symbol>,
    pub(crate) produces: HashMap<&'d Symbol, (), BuildHasher_Symbol>,
    pub(crate) cost: RuleCost,
}

impl<'d, Symbol> Rule<'d, Symbol>
where
    Symbol: Eq + Hash + Clone + Ord,
{
    /// Creates a new rule, adding its [`Symbol`]s to this [`Domain`] as necessary.
    ///
    /// The new rule will have its index set to [`RULE_IX_INVALID`].
    pub fn new_rule_and_symbols<'a, 'b, RS_II, RS_II_AsRef_Symbol, PS_II, PS_II_AsRef_Symbol>(
        domain: &'d mut Domain<Symbol>,
        requires_iter: RS_II,
        produces_iter: PS_II,
        cost: RuleCost,
    ) -> Result<Rule<'d, Symbol>>
    where
        RS_II: IntoIterator<Item = RS_II_AsRef_Symbol> + Clone,
        RS_II_AsRef_Symbol: std::convert::AsRef<Symbol> + 'a,
        PS_II: IntoIterator<Item = PS_II_AsRef_Symbol> + Clone,
        PS_II_AsRef_Symbol: std::convert::AsRef<Symbol> + 'b,
    {
        let build_hasher_symbol = domain.build_hasher_symbol().clone();

        for s in requires_iter.clone() {
            let s: &Symbol = s.as_ref();
            domain.ensure_symbol(s)?; // keep no reference in this loop
        }

        for s in produces_iter.clone() {
            let s: &Symbol = s.as_ref();
            domain.ensure_symbol(s)?; // keep no reference in this loop
        }

        Self::new_rule(domain, requires_iter, produces_iter, cost)
    }

    /// Creates a new rule, where all its [`Symbol`]s are already present in the [`Domain`].
    ///
    /// The new rule will have its index set to [`RULE_IX_INVALID`].
    pub fn new_rule<'a, 'b, RS_II, RS_II_AsRef_Symbol, PS_II, PS_II_AsRef_Symbol>(
        domain: &'d Domain<Symbol>,
        requires_iter: RS_II,
        produces_iter: PS_II,
        cost: RuleCost,
    ) -> Result<Rule<'d, Symbol>>
    where
        RS_II: IntoIterator<Item = RS_II_AsRef_Symbol> + Clone,
        RS_II_AsRef_Symbol: std::convert::AsRef<Symbol> + 'a,
        PS_II: IntoIterator<Item = PS_II_AsRef_Symbol> + Clone,
        PS_II_AsRef_Symbol: std::convert::AsRef<Symbol> + 'b,
    {
        let mut requires = HashMap::with_hasher(domain.build_hasher_symbol().clone());
        for s in requires_iter {
            // Unwrap() is justified here because we just called `ensure_symbol()` on each one.
            #[allow(clippy::unwrap_used)]
            let s: &'d Symbol = domain.get_existing_symbol(s.as_ref()).unwrap();
            requires.insert(s, ());
        }

        let mut produces = HashMap::with_hasher(domain.build_hasher_symbol().clone());
        for s in produces_iter {
            // Unwrap() is justified here because we just called `ensure_symbol()` on each one.
            #[allow(clippy::unwrap_used)]
            let s: &'d Symbol = domain.get_existing_symbol(s.as_ref()).unwrap();
            produces.insert(s, ());
        }

        let rule = Self {
            domain,
            ix: RULE_IX_INVALID,
            requires,
            produces,
            cost,
        };

        Ok(rule)
    }
}

impl<'d, Symbol> Rule<'d, Symbol>
where
    Symbol: Eq + Hash,
{
    /// Returns rule's Domain.
    pub fn domain(&self) -> &'d Domain<Symbol> {
        self.domain
    }

    /// Returns rule index, if it is valid.
    pub fn ix(&self) -> Option<usize> {
        let ix = self.ix;
        (ix != RULE_IX_INVALID).then_some(ix)
    }

    /// Returns iterator over the [`Symbols`] this rule `requires`.
    pub fn requires(&self) -> impl ExactSizeIterator<Item = &Symbol> + FusedIterator {
        self.requires.keys().copied()
    }

    /// Returns iterator over the [`Symbols`] this rule `produces`.
    pub fn produces(&self) -> impl ExactSizeIterator<Item = &Symbol> + FusedIterator {
        self.produces.keys().copied()
    }

    /// Returns the rule's [`cost`](RuleCost).
    pub fn cost(&self) -> RuleCost {
        self.cost
    }

    /*
    /// Returns access to the [`BuildHasher`](std::hash::BuildHasher) used for hashing [`Symbol`]s.
    pub fn build_hasher_symbol(&self) -> &BuildHasher_Symbol {
        self.requires.hasher()
    }

    /// Hashes a [`Symbol`].
    pub fn hash_symbol(&self, symbol: &Symbol) -> u64 {
        self.build_hasher_symbol().hash_one(symbol)
    }
    // */
}

impl<'d, Symbol> PartialEq for Rule<'d, Symbol>
where
    Symbol: Eq + Hash + Ord + 'd,
{
    #[inline]
    fn eq(&self, rhs: &Self) -> bool {
        self.ix == rhs.ix
            && self.requires == rhs.requires
            && self.produces == rhs.produces
            && self.cost == rhs.cost
    }
}

impl<'d, Symbol> Eq for Rule<'d, Symbol> where Symbol: Eq + Hash + Ord + 'd {}

impl<'d, Symbol> std::fmt::Debug for Rule<'d, Symbol>
where
    Symbol: Eq + Hash + Ord + std::fmt::Debug + 'd,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("Rule");
        ds.field("ix", &self.ix);
        ds.field("requires", &self.requires);
        ds.field("produces", &self.produces);
        ds.field("cost", &self.cost);
        ds.finish()
    }
}

impl<'d, Symbol> std::fmt::Display for Rule<'d, Symbol>
where
    Symbol: Eq + Hash + Ord + std::fmt::Display + 'd,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("Rule");
        ds.field("ix", &self.ix);

        /*
        let v_symbol_to_string = |symbols: &Vec<Symbol>| -> String {
            let mut s = "[".to_string();
            for (&symbol, _) in self.requires.iter() {
                s.push_str(&format!("\n    {symbol}"));
            }
            s.push_str("\n]");
            s
        };
        // */

        let hm_symbol_to_string = |symbols: &HashMap<&Symbol, (), _>| -> String {
            let mut s = "[".to_string();
            for (&symbol, _) in self.requires.iter() {
                s.push_str(&format!("\n    {symbol}"));
            }
            s.push_str("\n]");
            s
        };

        ds.field("requires", &hm_symbol_to_string(&self.requires));
        ds.field("produces", &hm_symbol_to_string(&self.produces));
        ds.field("cost", &format_args!("{}", self.cost));
        ds.finish()
    }
}

/*
pub(crate) struct HashSetSymbolWrapper<'a, Symbol, BuildHasher_Symbol>(
    pub(crate) &'a HashMap<Symbol, (), BuildHasher_Symbol>
);
impl <'a, Symbol, BuildHasher_Symbol> HashSetSymbolWrapper<'a, Symbol, BuildHasher_Symbol> {

}
impl serde::Serialize for HashSetSymbolWrapper<'_, Symbol, BuildHasher_Symbol>{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::{
            Error,
            SerializeSeq,
        };
        let mut state = serializer.serialize_seq(Some(self.0.len()))?;
        for elem in self {
            state.serialize_element(elem)?;
        }
        state.end()
    }
}
// */

//=================================================================================================|

/*
#[derive(Clone, Debug, PartialEq, Eq //, Hash
)]
pub(crate) struct Rule_Sym {
    id: usize,
    requires: HashMap<SymRepr, (), BuildHasher_Sym>,
    produces: HashMap<SymRepr, (), BuildHasher_Sym>,
    cost: RuleCost,
}
pub struct RuleKey<Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    SetU32,
}
#[derive(Clone//, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash
)]
pub struct Rules {
    rules: HashMap<RuleKey, RuleValue>,
}
//

impl Rule {
    pub fn new(requires: &str, produces: &str, cost: i64) -> Result<Rule> {

impl std::fmt::Display for Rule {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl arbitrary::Arbitrary<'_> for Rule {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut requires: SymSet = u.arbitrary()?;
        let mut produces: SymSet = u.arbitrary()?;

        // Most of the time we want the [`produces`] set at least as large as the [`requires`] set.
        if u.ratio(9, 10)? && produces.len() < requires.len() {
            (produces, requires) = (requires, produces);
        }

        Ok(Rule {
            requires,
            produces,
            cost: u.int_in_range::<i64>(1..=1_000_000)?,
        })
    }
}

impl proptest::arbitrary::Arbitrary for Rule {
    type Parameters = ();
    type Strategy = proptest_arbitrary_interop::ArbStrategy<Self>;

    fn arbitrary_with(_top: Self::Parameters) -> Self::Strategy {
        proptest_arbitrary_interop::arb()
    }
}
// */

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    //?use anyhow::{anyhow, bail, ensure, Context, Result};
    //?use insta::assert_ron_snapshot;
    use super::*;

    /*
    use proptest::prelude::*;
    proptest! {
        //#![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn rule(rule: Rule) {
            let s = rule.to_string();
        }
    }
    // */
}
