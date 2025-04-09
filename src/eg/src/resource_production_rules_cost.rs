// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
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

//use crate::{};

//=================================================================================================|

/// General categories of cost for one step of resource production.
///
/// The exact values are never persisted and subject to change as needed.
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum CostCategory {
    /// Cost of retrieval from cache, e.g., cloning an [`Arc<T>`](std::sync::Arc).
    ExistsInCache = 0x0030_0000,

    /// Cost of extracting a sub-field from a larger resource.
    Extraction = 0x0032_0000,

    /// Derive without having to perform validation checks.
    ///
    /// E.g., un-validation, serialization, or deserialization from/to a memory buffer.
    Derivation = 0x0050_0000,

    /// Validation checks.
    Validation = 0x0070_0000,

    /// Read/write data to/from local disk.
    ToFromDisk = 0x0090_0000,

    /// Read/write data to/from disk.
    ToFromNetwork = 0x00B0_0000,

    /// Generate example data.
    #[cfg(any(feature = "eg-allow-test-data-generation", test))]
    ExampleData = 0x00D0_0000,
}

/// Cost
pub struct Cost {
    /// General cost category. Just guidelines, really.
    category: CostCategory,

    /// Adjustment to cost category. Since the [`CostCategory`] values are 0x0020_0000 apart,
    /// it probaby makes sense to keep this value within +- 0x0010_0000, but it is
    /// intended to be allowed to adjust into the range of a higher or lower category
    /// if necessary.
    adjustment: i32,
}

impl Cost {
    /// General cost category.
    pub fn category(&self) -> CostCategory {
        self.category
    }

    /// Adjustment to cost category.
    pub fn adjustment(&self) -> i32 {
        self.adjustment
    }
}

impl PartialEq for Cost {
    fn eq(&self, rhs: &Self) -> bool {
        let lhs: i32 = self.into();
        let rhs: i32 = rhs.into();
        lhs == rhs
    }
}

impl Eq for Cost {}

impl PartialOrd for Cost {
    fn partial_cmp(&self, rhs: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(rhs))
    }
}

impl Ord for Cost {
    fn cmp(&self, rhs: &Self) -> std::cmp::Ordering {
        let lhs: i32 = self.into();
        let rhs: i32 = rhs.into();
        lhs.cmp(&rhs)
    }
}

impl std::hash::Hash for Cost {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "Cost".hash(state);
        i32::from(self).hash(state);
    }
}

impl From<&Cost> for i32 {
    /// An [`i32`] can always be made from a [`&Cost`].
    fn from(cost: &Cost) -> Self {
        (cost.category() as i32).saturating_add(cost.adjustment())
    }
}

impl From<Cost> for i32 {
    /// An [`i32`] can always be made from a [`Cost`].
    fn from(cost: Cost) -> Self {
        i32::from(&cost)
    }
}

//=================================================================================================|
