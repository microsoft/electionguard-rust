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
        sym::Sym,
        sym_set::SymSet,
    },
};

//=================================================================================================|

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub struct Rule {
    pub requires: SymSet,
    pub produces: SymSet,
    pub cost: i64,
}

impl Rule {
    pub fn new(requires: &str, produces: &str, cost: i64) -> Result<Rule> {
        let self_ = Rule {
            requires: requires.parse()?,
            produces: produces.parse()?,
            cost,
        };
        Ok(self_)
    }
}

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

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    //?use anyhow::{anyhow, bail, ensure, Context, Result};
    //?use insta::assert_ron_snapshot;
    use proptest::prelude::*;

    use super::*;

    proptest! {
        //#![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn rule(rule: Rule) {
            let s = rule.to_string();
        }
    }
}
