// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::ops::DerefMut;

use anyhow::{Context, Result, anyhow, bail, ensure};
//use either::Either;
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
use maybe_owned::{MaybeOwned, MaybeOwnedMut};
use util::{
    csrng::Csrng,
    vec1::{HasIndexType, Vec1},
};

use crate::{
    eg::Eg,
    //errors::{EgResult, EgValidateError},
    //example_election_manifest::example_election_manifest,
    //guardian::{GuardianIndex, GuardianKeyPurpose},
    //guardian_public_key::GuardianPublicKey,
    guardian_secret_key::GuardianSecretKey,
    //pre_voting_data::{self, PreVotingData},
    resource::{ProduceResource, ProduceResourceExt},
    //varying_parameters::VaryingParameters,
};

//=================================================================================================|

pub fn example_pre_voting_data(_eg: &mut Eg) -> Result<Vec1<GuardianSecretKey>> {
    bail!("this function has been superceeded")
}

pub fn example_pre_voting_data2(
    _produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    _varying_parameter_n: u32,
    _varying_parameter_k: u32,
) -> Result<Vec1<GuardianSecretKey>> {
    bail!("this function has been superceeded")
}

//=================================================================================================|

pub fn example_validation_info(
    _produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
) -> Result<(Eg, Vec1<GuardianSecretKey>)> {
    bail!("this function has been superceeded")
}

/// Creates an example [`PreVotingData`], specifying values for election varying parameters `n` and `k`.
pub fn example_validation_info2(
    _produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    _varying_parameter_n: u32,
    _varying_parameter_k: u32,
) -> Result<(Eg, Vec1<GuardianSecretKey>)> {
    bail!("this function has been superceeded")
}
