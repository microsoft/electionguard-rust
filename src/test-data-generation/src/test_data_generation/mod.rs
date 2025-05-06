// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(clippy::let_and_return)] //? TODO: Remove temp development code
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

mod persona;
pub use persona::*;

pub mod council;
pub use council::*;

pub mod hash_lcg;
pub use hash_lcg::*;

//=================================================================================================|

#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    borrow::{
        Cow,
        //Borrow,
    },
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //hash::{BuildHasher, Hash, Hasher},
    //io::{BufRead, Cursor},
    //iter::zip,
    //marker::PhantomData,
    //path::{Path, PathBuf},
    //process::ExitCode,
    //rc::Rc,
    //str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
        LazyLock,
    },
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use futures_lite::future::{self, FutureExt};
//use hashbrown::HashMap;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::*;

//=================================================================================================|

/// This generator produces test data. An instance of this generator ensures no repetition.
#[derive()]
pub struct TestDataGenerator {
    next_persona_seed: AtomicU64,
}

impl TestDataGenerator {
    /// Initializes a new [`TestDataGenerator`] from a sequence of seed data bytes.
    #[inline]
    pub fn from_seed_bytes<AsRefSliceU8>(seed_bytes: AsRefSliceU8) -> Self
    where
        AsRefSliceU8: AsRef<[u8]>,
    {
        let seed_bytes = seed_bytes.as_ref();
        Self {
            next_persona_seed: AtomicU64::new(0),
        }
    }

    /*
    pub fn unique_personae(&mut self, cnt: usize) -> impl IntoIterator<Item = Arc<Persona>> {
        std::iter::from_fn()
    }
    // */
}

impl std::fmt::Debug for TestDataGenerator {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for TestDataGenerator {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestDataGenerator { .. }")
    }
}

//=================================================================================================|
