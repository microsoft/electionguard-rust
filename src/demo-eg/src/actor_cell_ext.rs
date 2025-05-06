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
    //borrow::{
        //Cow,
        //Borrow,
    //},
    //cell::RefCell,
    //marker::PhantomData,
    //str::FromStr,
    //sync::{
        //Arc,
        //OnceLock,
    //},
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use futures_lite::future::{self, FutureExt};
use ractor::{
    Actor,
    ActorProcessingErr,
    ActorRef,
    async_trait, //cast
};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};

//=================================================================================================|

//#[async_trait]
pub trait ActorCellExt
where
    Self: std::ops::Deref<Target = ractor::actor::actor_cell::ActorCell>,
{
    /// Returns the actor's id and name as a [`String`].
    fn id_name(&self) -> String {
        let id = self.get_id();
        if let Some(name) = self.get_name() {
            format!("{id}:{name}")
        } else {
            id.to_string()
        }
    }
}

impl<T> ActorCellExt for T where T: std::ops::Deref<Target = ractor::actor::actor_cell::ActorCell> {}
