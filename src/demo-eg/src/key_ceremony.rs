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
        Arc,
        //OnceLock,
    },
};

use anyhow::{Context, Result, anyhow, bail, ensure};
//use either::Either;
//use futures_lite::future::{self, FutureExt};
//use hashbrown::HashMap;
use ractor::{
    Actor,
    ActorProcessingErr,
    ActorRef,
    async_trait, //, cast
};
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
//use zeroize::{Zeroize, ZeroizeOnDrop};

//
use eg::eg::Eg;

use crate::{
    actor_cell_ext::ActorCellExt,
    //key_ceremony::key_ceremony,
    router::Router,
};

//=================================================================================================|

#[instrument(name = "key_ceremony", skip(eg), ret)]
pub async fn key_ceremony(eg: &Arc<Eg>) -> Result<()> {
    eprintln!("in key_ceremony");

    let router_actorname = Router::preferred_actorname();
    let opt_router_actorname = Some(router_actorname.clone());

    let router_startup_args = ();

    let op_spawn_router_msg_string = format!(
        "Spawning `{router_actorname}` from thread `{:?}`",
        std::thread::current().id()
    );
    info!("{op_spawn_router_msg_string}");
    let (router_actor, router_handle) =
        Actor::spawn(opt_router_actorname, Router, router_startup_args)
            .await
            .context(op_spawn_router_msg_string)?;

    let router_idname = router_actor.id_name();
    info!("Spawned: `{router_idname}`");

    let op_join_router_handle_msg_string = format!("Joining handle for `{router_idname}`");
    info!("{op_join_router_handle_msg_string}");
    router_handle
        .await
        .map_err(|_| anyhow::Error::msg(op_join_router_handle_msg_string))?;
    info!("Joined handle for `{router_idname}`");

    Ok(())
}
