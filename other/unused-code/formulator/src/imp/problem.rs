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

#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    borrow::Cow,
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    //iter::zip,
    hash::{BuildHasher, Hash, Hasher},
    //marker::PhantomData,
    //path::{Path, PathBuf},
    //sync::Arc,
    //str::FromStr,
    //sync::OnceLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
use hashbrown::HashMap;
use indoc::indoc;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Domain, DynFnRefSymbolToCowstr, Rule, RuleCost, RuleCostSum,
    error::{Error, Result},
    imp::{BuildHasher_Sym, BuildHasher_Symbol, MAX_SYMREPR, SymRepr, SymSetRepr, reserve_addl},
};

//=================================================================================================|

#[derive(Clone)]
pub struct Problem<'d, Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    pub(crate) domain: &'d Domain<Symbol>,

    pub(crate) starting_set: HashMap<Symbol, (), BuildHasher_Symbol>,
    pub(crate) finishing_set: HashMap<Symbol, (), BuildHasher_Symbol>,

    pub(crate) rules: Vec<Rule<'d, Symbol>>,
}

impl<'d, Symbol> Problem<'d, Symbol>
where
    Symbol: Eq + Hash + Clone + Ord,
{
    pub fn new<SS_II, SS_II_Symbol, FS_II, FS_II_Symbol>(
        domain: &'d Domain<Symbol>,
        starting_set_iter: SS_II,
        finishing_set_iter: FS_II,
    ) -> Self
    where
        SS_II: IntoIterator<Item = SS_II_Symbol>,
        SS_II_Symbol: std::borrow::Borrow<Symbol>,
        FS_II: IntoIterator<Item = FS_II_Symbol>,
        FS_II_Symbol: std::borrow::Borrow<Symbol>,
    {
        let build_hasher_symbol = domain.build_hasher_symbol().clone();

        let mut starting_set = HashMap::with_hasher(build_hasher_symbol.clone());
        for s in starting_set_iter {
            starting_set.insert(s.borrow().clone(), ());
        }

        let mut finishing_set = HashMap::with_hasher(build_hasher_symbol);
        for s in finishing_set_iter {
            finishing_set.insert(s.borrow().clone(), ());
        }

        Self {
            domain,
            starting_set,
            finishing_set,
            rules: Vec::new(),
        }
    }
}

impl<'d, Symbol> Problem<'d, Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    /// Returns access to the [`Domain`].
    pub(crate) fn domain(&self) -> &'d Domain<Symbol> {
        self.domain
    }

    /// Adds a new rule to the Domain. Also adds all Symbols mentioned by the rule.
    ///
    /// Returns the index of the new rule.
    pub fn add_rule(&mut self, mut rule: Rule<'d, Symbol>) -> Result<usize> {
        let rule_ix = self.rules.len();

        //? TODO If another rule which is at least as powerful with no less cost
        // does not exist already, return the existing rule?

        if rule_ix >= crate::RULES_CNT_MAX {
            return Err(Error::RuleSetFull {
                current_number: self.rules.len(),
            });
        }

        rule.ix = rule_ix;
        self.rules.push(rule);

        Ok(rule_ix)
    }
}

impl<'d, Symbol> std::fmt::Debug for Problem<'d, Symbol>
where
    Symbol: Eq + Hash + Ord + std::fmt::Debug,
{
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            indoc! {"
            Problem {{
                starting_set: {:?},
                finishing_set: {:?},
                rules: [
        "},
            self.starting_set, self.finishing_set
        )?;

        for (ix, r) in self.rules.iter().enumerate() {
            writeln!(f, "        {ix:4}: {r:?}")?;
        }

        write!(
            f,
            indoc! {"
                ],
            }}"}
        )
    }
}

impl<'d, Symbol> std::fmt::Display for Problem<'d, Symbol>
where
    Symbol: Eq + Hash + Ord + std::fmt::Debug,
{
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/*
impl arbitrary::Arbitrary<'_> for Problem {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut starting_set: SymSet = u.arbitrary()?;
        let mut finishing_set: SymSet = u.arbitrary()?;

        // Most of the time we want the starting set at least as large as the finishing set.
        if u.ratio(9, 10)? && starting_set.len() < finishing_set.len() {
            (starting_set, finishing_set) = (finishing_set, starting_set);
        }

        // Most of the time we want some rules
        let mut rules: Vec<Rule> = Vec::new();
        if u.ratio(19, 20)? {
            let mut n: usize = 1;
            for _ in 0..4 {
                n += u.arbitrary::<u32>()?.leading_ones() as usize;
            }
            while rules.len() < n && !u.is_empty() {
                let rule: Rule = u.arbitrary()?;
                let rule_exists = rules
                    .iter()
                    .any(|r2| r2.requires == rule.requires && r2.produces == rule.produces);
                if !rule_exists {
                    rules.push(rule);
                }
            }
        }

        // Ensure at least 1/4 of the rules include only elements from the starting set
        for rule in rules.iter_mut() {
            if !starting_set.is_empty() && u.ratio(1, 4)? {
                rule.requires &= &starting_set;
            }
        }

        // Ensure at least 1/4 of the rules produce at least one element of the finishing set
        for rule in rules.iter_mut() {
            if !finishing_set.is_empty() && u.ratio(1, 4)? {
                let sym = u.choose_iter(finishing_set.iter())?;
                rule.produces |= sym;
            }
        }

        Ok(Problem {
            starting_set,
            finishing_set,
            rules,
        })
    }
}

impl proptest::arbitrary::Arbitrary for Problem {
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
    //use anyhow::{anyhow, bail, ensure, Context, Result};
    //?use insta::assert_ron_snapshot;
    use proptest::prelude::*;

    use super::*;

    /*
    // [`Problem`] tests
    proptest! {
        #[test]
        fn sym_arbitrary(_problem: Problem) {
            //prop_assert!();
        }
    }
    // */
}
