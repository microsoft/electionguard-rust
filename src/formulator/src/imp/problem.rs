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
use indoc::indoc;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::{Error, Result},
    imp::{
        rule::Rule,
        sym::Sym,
        sym_set::SymSet,
    },
};

//=================================================================================================|

#[derive(Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct Problem {
    pub starting_set: SymSet,
    pub finishing_set: SymSet,
    pub rules: Vec<Rule>,
}

impl Problem {
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

impl std::fmt::Debug for Problem {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            indoc! {"
            Problem {{
                starting_set: {},
                finishing_set: {},
                rules: [
        "},
            self.starting_set, self.finishing_set
        )?;
        for (ix, r) in self.rules.iter().enumerate() {
            writeln!(f, "        {ix:4}: {r}")?;
        }
        write!(f, indoc! {"
                ],
            }}"})
    }
}

impl std::fmt::Display for Problem {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

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

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    //use anyhow::{anyhow, bail, ensure, Context, Result};
    //?use insta::assert_ron_snapshot;
    use proptest::prelude::*;

    use super::*;

    // [`Problem`] tests
    proptest! {
        #[test]
        fn sym_arbitrary(_problem: Problem) {
            //prop_assert!();
        }
    }
}
