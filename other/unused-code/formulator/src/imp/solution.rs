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
    Domain, DynFnRefSymbolToCowstr, Problem, Rule, RuleCost, RuleCostSum,
    error::{Error, Result},
    imp::{BuildHasher_Sym, BuildHasher_Symbol, MAX_SYMREPR, SymRepr, SymSetRepr, reserve_addl},
};

//=================================================================================================|

#[derive(Clone)]
pub struct Solution<'d: 'p, 'p, Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    domain: &'d Domain<Symbol>,
    problem: &'p Problem<'d, Symbol>,

    build_hasher_sym: BuildHasher_Sym,

    symbol_to_sym: HashMap<Symbol, SymRepr, BuildHasher_Symbol>,
    sym_to_symbol: HashMap<SymRepr, Symbol, BuildHasher_Sym>,
}

impl<'d: 'p, 'p, Symbol> Solution<'d, 'p, Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    /// Creates a new [`Solution`], or at least space for solving.
    ///
    /// - `problem` - The problem, references the [`Domain`].
    /// - `seed` - Seed data with which to initialize data structure hash function.
    pub fn new<H: Hash>(problem: &'p Problem<'d, Symbol>, seed: H) -> Self {
        let domain: &'d Domain<Symbol> = problem.domain();

        let build_hasher_symbol = domain.build_hasher_symbol().clone();

        let [build_hasher_sym] = crate::imp::hasher::BuildHasher_StableSipHasher128::new_arr(seed);

        let symbol_to_sym = HashMap::with_hasher(build_hasher_symbol);
        let sym_to_symbol = HashMap::with_hasher(build_hasher_sym.clone());

        Self {
            domain,
            problem,
            build_hasher_sym,
            symbol_to_sym,
            sym_to_symbol,
        }
    }

    /// Hashes a [`SymRepr`].
    pub(crate) fn hash_sym(&self, sym: SymRepr) -> u64 {
        self.build_hasher_sym.hash_one(sym)
    }

    /// Attempts to convert a [`T: TryInto<u32>`](std::convert::TryInto) to a [`SymRepr`].
    pub fn sym_try_from<T>(src: T) -> Option<SymRepr>
    where
        T: TryInto<u32>,
    {
        #[allow(clippy::absurd_extreme_comparisons)]
        <T as TryInto<u32>>::try_into(src)
            .ok()
            .filter(|&sym| sym <= MAX_SYMREPR)
    }

    /// Returns the total number of syms that have been mapped from Symbols.
    pub fn cnt_syms(&self) -> usize {
        let cnt = self.symbol_to_sym.len();
        debug_assert_eq!(cnt, self.sym_to_symbol.len());
        cnt
    }

    /*
        pub fn successors(&self, ss_from: SymSet) -> impl Iterator<Item = (SymSet, i64)> + use<> {
            let ss_from2 = &ss_from;
            let mut filter_map_rule = &mut move |rule: &Rule| {
                let ss_from3 = ss_from2;
                let ss_rule_requires_and_ss_from = rule.requires.clone() & ss_from3;
                (&rule.requires == &ss_rule_requires_and_ss_from)
                    .then(|| (ss_from.clone() | &rule.produces, rule.cost))
            };
            self.rules.iter().filter_map(filter_map_rule)
        }
    // */
}

impl<'d: 'p, 'p, Symbol> Solution<'d, 'p, Symbol>
where
    Symbol: Eq + Hash + Ord + Clone,
{
    /// Gets the [`SymRepr`] for a [`Symbol`], or assigns a new one if it does not exist.
    ///
    /// You probably don't want to call this. Let the system manage the creation of syms.
    pub fn get_or_assign_sym_repr<'s>(&mut self, symbol: &'s Symbol) -> Result<SymRepr> {
        use hashbrown::hash_map::{
            RawEntryBuilderMut,
            RawEntryMut::{self, *},
        };

        // insert into symbols
        let (opt_symbol_entry, symbol_hash_u64): (Option<&'d Symbol>, u64) =
            self.domain.get_existing_symbol_hashvalue(symbol);

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

            let symbol_to_sym_len = self.symbol_to_sym.len();

            let symbol_to_sym_raw_entry_mut = self
                .symbol_to_sym
                .raw_entry_mut()
                .from_hash(symbol_hash_u64, is_symbol_match);

            match symbol_to_sym_raw_entry_mut {
                Occupied(entry) => (false, *entry.get()),
                Vacant(entry) => {
                    // pick the next sym value
                    let Some(sym) = Self::sym_try_from(symbol_to_sym_len) else {
                        let opt_symbol_str = self.domain.try_symbol_to_str(symbol);
                        return Err(Error::SymbolSetFull {
                            opt_symbol_str,
                            current_number: self.cnt_syms(),
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
}

impl<'d, 'p, Symbol> std::fmt::Debug for Solution<'d, 'p, Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        /*
        writeln!(f, "    }},\n    symbol_to_sym: {{")?;

        for (symbol, sym) in self.symbol_to_sym.iter() {
            writeln!(f, "        {symbol:?} -> {sym:?},")?;
        }

        writeln!(f, "    }},\n    sym_to_symbol: {{")?;

        for (sym, symbol) in self.sym_to_symbol.iter() {
            writeln!(f, "        {sym:?} -> {symbol:?},")?;
        }

        writeln!(f, "    }},\n    rules: [")?;

        for (ix, r) in self.rules.iter().enumerate() {
            writeln!(f, "        {ix:4}: {r:?},")?;
        }
        write!(f, "    ],\n}}")
        // */

        write!(f, "Solution") //? TODO
    }
}

impl<'d, 'p, Symbol> std::fmt::Display for Solution<'d, 'p, Symbol>
where
    Symbol: Eq + Hash + Ord,
{
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Solution") //? TODO
    }
}

/*
impl proptest::arbitrary::Arbitrary for Solution {
    type Parameters = ();
    type Strategy = proptest_arbitrary_interop::ArbStrategy<Self>;

    fn arbitrary_with(_top: Self::Parameters) -> Self::Strategy {
        proptest_arbitrary_interop::arb()
    }
}
// */

//=================================================================================================|

/*
pub fn find_solutions(pr: &Problem) -> impl IntoIterator<Item = Solution> {

    let starting_set = pr.starting_set.clone();
    let pr_finishing_set = pr.finishing_set.clone();

    let mut success = |ss: &SymSet| ss.contains_all_of(&pr_finishing_set);

    /*
    let mut heuristic = |_ss_from: &SymSet| {
        // "must not be greater than the real cost, or a wrong shortest path may be returned"
        0
    };

    let opt_v_c = pathfinding::directed::fringe::fringe(
        &start,
        successors,
        heuristic,
        success);
    // */

    pub struct SuccessorsIter<'a> {
        ss_from: SymSet,
        rules: &'a Vec<Rule>,
        next_rule_ix: usize,
    }

    impl SuccessorsIter<'_> {
        pub fn new<'a>(rules: &'a Vec<Rule>, ss_from: SymSet) -> SuccessorsIter<'a> {
            SuccessorsIter {
                rules,
                ss_from,
                next_rule_ix: 0,
            }
        }
    }

    impl<'a> Iterator for SuccessorsIter<'a> {
        type Item = (SymSet, i64);

        fn next(&mut self) -> Option<Self::Item> {
            while self.next_rule_ix < self.rules.len() {
                let this_rule_ix = self.next_rule_ix;
                self.next_rule_ix += 1;

                let this_rule = &self.rules[this_rule_ix];
                if self.ss_from.contains_all_of(&this_rule.requires) {
                    let node = self.ss_from.clone() | &this_rule.produces;
                    let cost: i64 = this_rule.cost;
                    //println!("{} -> {} for {}", &this_rule.requires, &node, cost);
                    return Some((node, cost));
                }
            }
            None
        }
    }

    let successors = |ss_from: &SymSet| {
        SuccessorsIter::new(&pr.rules, ss_from.clone())
    };

    use pathfinding::directed::dijkstra::dijkstra;
    let opt_v_c = dijkstra(&starting_set, successors, success);

    let mut opt_solution: Option<Solution> = None;

    if let Some((path, cost)) = opt_v_c {
        let so = Solution { path, cost };
        let _ = opt_solution.insert(so);
    }

    opt_solution.into_iter()
}
// */

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(unknown_lints, clippy::literal_string_with_formatting_args)]
mod t {
    use proptest::prelude::*;

    use super::*;
    /*
        proptest! {
            //#![proptest_config(ProptestConfig::with_cases(10))]
            #[test]
            fn t_find_solutions(pr: Problem) {
                //println!("vvvvvvvvvvvvvvvvvvvvvvv proptest find_solutions vvvvvvvvvvvvvvvvvvvvvvv");
                //println!("Problem: {pr:?}");
                let _v_so: Vec<Solution> = find_solutions(&pr).into_iter().collect::<Vec<_>>();
                //if !_v_so.is_empty() {
                //    eprintln_problem_solutions(&pr, v_so.as_slice());
                //}
                //println!("^^^^^^^^^^^^^^^^^^^^^^^ proptest find_solutions ^^^^^^^^^^^^^^^^^^^^^^^");
            }
        }

        #[test]
        #[rustfmt::skip]
        fn t() {
            let a = [
                (      "{}",     "{a}", Some(    10 )),
                (     "{a}",   "{a,b}", Some(   100 )),
                (      "{}",   "{a,b}", Some(   110 )),
                (   "{a,b}",   "{a,b}", Some(     0 )),
                (   "{a,b}",     "{a}", Some(     0 )),
                (   "{a,b}",     "{b}", Some(     0 )),
                (   "{a,b}",      "{}", Some(     0 )),
                (      "{}", "{a,b,c}", Some(  1110 )),
                (      "{}",   "{b,c}", Some(  1110 )),
                ( "{a,b,c}",      "{}", Some(     0 )),
                ( "{a,b,c}",     "{z}", None         ),
                (     "{c}", "{a,b,c}", Some(    10 )),
                (      "{}",     "{d}", Some( 11110 )),
                (     "{d}",     "{e}", Some(    10 )),
                (     "{d}",     "{f}", Some(    20 )),
                (     "{d}",     "{g}", Some(    30 )),
                (     "{d}",     "{h}", Some(    40 )),
                (     "{d}",     "{i}", Some(    50 )),
                (     "{d}",     "{j}", Some(    11 )), // d -> abcd -> abcdj
            ];
            for (ss, fs, opt_c) in a {
                test_from_to(ss, fs, opt_c);
            }
        }

        #[rustfmt::skip]
        fn test_from_to(starting_set: &str, finishing_set: &str, opt_expected_cost: Option<i64>) {
            let pr = Problem {
                starting_set: starting_set.parse().unwrap(),
                finishing_set: finishing_set.parse().unwrap(),
                rules: [
                    // requires, produces, cost
                    Rule::new(    "{}",     "{a}",    10 ),
                    Rule::new(   "{a}",     "{b}",   100 ),
                    Rule::new( "{a,b}",     "{c}",  1000 ),
                    Rule::new(   "{c}", "{a,b,c}",    10 ),
                    Rule::new(   "{c}",   "{b,d}", 10000 ),
                    Rule::new(   "{d}", "{a,b,c}",     1 ),
                    Rule::new(   "{d}",     "{e}",    10 ),
                    Rule::new(   "{e}",     "{f}",    10 ),
                    Rule::new(   "{f}",     "{g}",    10 ),
                    Rule::new(   "{g}",     "{h}",    10 ),
                    Rule::new(   "{h}",     "{i}",    10 ),
                    Rule::new(   "{i}",     "{j}",    10 ),
                    Rule::new(   "{a}",     "{j}",    10 ),
                ].into_iter()
                .map(Result::unwrap)
                .collect(),
            };

            let v_so: Vec<Solution> = find_solutions(&pr).into_iter().collect::<Vec<_>>();

            let mut success = false;
            if let Some(expected_cost) = opt_expected_cost {
                if v_so.len() == 1 {
                    let so = &v_so[0];
                    success = so.cost == expected_cost;
                }
            } else {
                success = v_so.is_empty();
            }

            if !success {
                println!();
                eprintln_problem_solutions(&pr, v_so.as_slice());
                assert!(success);
            }
            //else { println!(""); eprintln_problem_solutions(&pr, v_so.as_slice()); }
        }

        fn eprintln_problem_solutions(pr: &Problem, solutions: &[Solution]) {
            println!("vvvvvvvvvvvvvvvvvvvvvvv problem, solutions vvvvvvvvvvvvvvvvvvvvvvv");
            println!("Problem: {pr:?}");

            if solutions.is_empty() {
                println!("Found {} solutions.", solutions.len());
            } else {
                if solutions.len() == 1 {
                    println!("Found {} solution:", solutions.len());
                } else {
                    println!("Found {} solutions:", solutions.len());
                }
                for solution in solutions {
                    for line in format!("{solution:#?}").lines() {
                        println!("    {line}");
                    }
                }
            }
            println!("^^^^^^^^^^^^^^^^^^^^^^^ problem, solutions ^^^^^^^^^^^^^^^^^^^^^^^");
        }
    // */
}
