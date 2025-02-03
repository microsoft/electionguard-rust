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

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::{Error, Result},
    imp::{
        problem::Problem,
        rule::Rule,
        sym::Sym,
        sym_set::SymSet,
    },
};

//=================================================================================================|

#[derive(Clone, Debug, derive_arbitrary::Arbitrary, serde::Deserialize, serde::Serialize)]
pub struct Solution {
    pub path: Vec<SymSet>,
    pub cost: i64,
}

impl proptest::arbitrary::Arbitrary for Solution {
    type Parameters = ();
    type Strategy = proptest_arbitrary_interop::ArbStrategy<Self>;

    fn arbitrary_with(_top: Self::Parameters) -> Self::Strategy {
        proptest_arbitrary_interop::arb()
    }
}

//=================================================================================================|

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
                    //eprintln!("{} -> {} for {}", &this_rule.requires, &node, cost);
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

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(unknown_lints, clippy::literal_string_with_formatting_args)]
mod t {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        //#![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn t_find_solutions(pr: Problem) {
            //println!("vvvvvvvvvvvvvvvvvvvvvvv proptest find_solutions vvvvvvvvvvvvvvvvvvvvvvv");
            //eprintln!("Problem: {pr:?}");
            let _v_so: Vec<Solution> = find_solutions(&pr).into_iter().collect::<Vec<_>>();
            //if !_v_so.is_empty() {
            //    eprintln_problem_solutions(&pr, v_so.as_slice());
            //}
            //eprintln!("^^^^^^^^^^^^^^^^^^^^^^^ proptest find_solutions ^^^^^^^^^^^^^^^^^^^^^^^");
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
            eprintln!();
            eprintln_problem_solutions(&pr, v_so.as_slice());
            assert!(success);
        }
        //else { eprintln!(""); eprintln_problem_solutions(&pr, v_so.as_slice()); }
    }

    fn eprintln_problem_solutions(pr: &Problem, solutions: &[Solution]) {
        eprintln!("vvvvvvvvvvvvvvvvvvvvvvv problem, solutions vvvvvvvvvvvvvvvvvvvvvvv");
        eprintln!("Problem: {pr:?}");

        if solutions.is_empty() {
            eprintln!("Found {} solutions.", solutions.len());
        } else {
            if solutions.len() == 1 {
                eprintln!("Found {} solution:", solutions.len());
            } else {
                eprintln!("Found {} solutions:", solutions.len());
            }
            for solution in solutions {
                for line in format!("{solution:#?}").lines() {
                    eprintln!("    {line}");
                }
            }
        }
        eprintln!("^^^^^^^^^^^^^^^^^^^^^^^ problem, solutions ^^^^^^^^^^^^^^^^^^^^^^^");
    }
}
