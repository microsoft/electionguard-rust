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
    //sync::{
        //Arc,
        //OnceLock,
    //},
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use futures_lite::future::{self, FutureExt};
//use hashbrown::HashMap;
use ractor::{Actor, ActorName, ActorProcessingErr, ActorRef, async_trait, cast};
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

//
use util::abbreviation::Abbreviation;

use eg::{
    eg::{Eg, EgConfig},
    election_parameters::ElectionParameters,
    fixed_parameters::{
        FixedParameters, FixedParametersInfo, FixedParametersTrait, FixedParametersTraitExt,
    },
    resource::{
        ElectionDataObjectId as EdoId, ProduceResource, ProduceResourceExt, Resource,
        ResourceFormat, ResourceId, ResourceIdFormat,
    },
    serializable::SerializablePretty,
    varying_parameters::{VaryingParameters, VaryingParametersInfo},
};

//
use crate::*;

//=================================================================================================|

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessageType {
    Ping,
    Pong,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Party {
    ElectionGuardian { label: String },
    ElectionAdministrator { label: String },
    Router,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Receiver {
    SpecificParty(Party),
    Everyone { including_router: bool },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouterMessage {
    sender: Party,
    receiver: Receiver,
    //? Logging publicly, or only in the context of a particular key ceremony?
    payload: MessageType,
}

impl RouterMessage {
    #[instrument]
    fn next(&self, myself_party: Party) -> Option<Self> {
        let RouterMessage {
            sender,
            receiver,
            payload,
        } = self;

        let is_for_me = match receiver {
            Receiver::SpecificParty(Party::Router) => true,
            Receiver::Everyone { including_router } => *including_router,
            _ => false,
        };

        if is_for_me {
            let sender = myself_party;

            let receiver = Receiver::SpecificParty(sender.clone());

            let payload = match payload {
                MessageType::Ping => MessageType::Pong, //?
                MessageType::Pong => MessageType::Ping, //?
            };

            let next_message = RouterMessage {
                sender,
                receiver,
                payload,
            };
            Some(next_message)
        } else {
            info!("RouterMessage is not for me: {:?}", receiver);
            None
        }
    }
}

#[derive(Debug)]
pub struct Router;

impl Router {
    pub fn preferred_actorname() -> ActorName {
        "Router".into()
    }

    pub const fn party_identity(&self) -> Party {
        Party::Router
    }
}

#[async_trait]
impl Actor for Router {
    type Msg = RouterMessage;
    type State = u8;
    type Arguments = ();

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        _args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let initial_state: Self::State = 0;

        // Send initial message.
        let message = RouterMessage {
            sender: self.party_identity(),
            receiver: Receiver::SpecificParty(Party::Router),
            payload: MessageType::Ping,
        };

        info!("{}: sending message: {message:?}", myself.id_name());
        cast!(myself, message)?;

        Ok(initial_state)
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        info!("Handling: {message:?}");

        //let my_actorname = myself.id_name();

        if *state < 10u8 {
            let myself_party = self.party_identity();
            if let Some(message) = message.next(myself_party) {
                cast!(myself, message)?;
                *state += 1;
            } else {
                info!("No message in response");
            }
        } else {
            info!("Stopping");
            //info!("{my_actorname}: stopping");
            myself.stop(None);
        }

        Ok(())
    }
}
