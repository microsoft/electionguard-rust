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

#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    borrow::Cow,
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //hash::{BuildHasher, Hash, Hasher},
    //io::{BufRead, Cursor},
    //iter::zip,
    //marker::PhantomData,
    //rc::Rc,
    //str::FromStr,
    sync::{
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

use crate::test_data_generation::persona::*;
use crate::*;

//=================================================================================================|

/*

pub struct Council {
    name: Cow<'static, str>,
    title_conferred_upon_council_members: Cow<'static, str>,
    members: Vec<PersonaIx>,
}

impl Council {
    pub fn new<N, T, M>(name: N, title_conferred_upon_council_members: T, members: M) -> Self
    where
        N: Into<Cow<'static, str>>,
        T: Into<Cow<'static, str>>,
        M: IntoIterator<Item = Arc<Persona>>,
    {
        Self {
            name: name.into(),
            title_conferred_upon_council_members: title_conferred_upon_council_members.into(),
            members: members.into_iter().collect(),
        }
    }
}

pub static COUNCILS: LazyLock<Vec<Council>> = LazyLock::new(|| {
    vec![Council::new(
        "Gränd Cøuncil of Arcáne and Technomägical Affairs",
        "Gränd Councillor",
        [
            "Elysêa Shadowbinder",
            "Lórenzo Starglýmmer",
            "Máriana Sùnshard",
            "Ìgnatius Gearsøul",
            "Óliver Stórmforge",
            "Séraphine Lùmenwing",
            "Cässandra Ætherweaver",
            "Bërnard Månesworn",
            "Lïliana Fîrestone",
            "Gavriel Sílverbolt",
            "Èlena Wîndwhisper",
            "Sébastien Skytöuch",
            "Vivîenne Rúnecrest",
            "Émeric Crystálgaze",
            "Océane Tidecaller",
            "Nikólai Thunderstrîde",
            "Cécilia Embergrâce",
            "Adrián Nightwíng",
            "Èmeline Glîmmerwillow",
            "Rãfael Stëamheart",
            "Cláudia Léafsinger",
            "Mïchael Moonrîse",
            "Anástasia Ëlementalstrider",
            "Lúcio Wîldheart",
            "Isabël Starshard",
        ]
        .map(|name| {
            let p = Persona::from_name(name);
            Arc::new(p)
        }),
    )]
});

// */
