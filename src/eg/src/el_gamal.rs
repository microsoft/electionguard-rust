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

use std::{
    //borrow::Cow,
    cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    //path::{Path, PathBuf},
    rc::Rc,
    //str::FromStr,
    //sync::OnceLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use util::{
    algebra::{FieldElement, Group, GroupElement, ScalarField},
    csrng::Csrng,
};

//=================================================================================================|

/// [`Result::Err`](std::result::Result) type of a data resource production operation.
#[derive(thiserror::Error, Debug, serde::Serialize)]
#[allow(non_camel_case_types)]
pub enum ElGamalError {
    #[error(
        "While attempting to borrow it shared, the cache for the `ElGamalPublicKey` is unexpecetedly already (mutably) in use: {_0}"
    )]
    TryBorrowSharedPubkeyCacheAlreadyMutablyInUse(String),

    #[error(
        "While attempting to borrow it for exclusive use, the cache for the `ElGamalPublicKey` is unexpecetedly already (mutably) in use: {_0}"
    )]
    TryBorrowExclusivePubkeyCacheAlreadyMutablyInUse(String),
}

/// [`Result`](std::result::Result) type with an [`ElGamalError`].
pub type ElGamalResult<T> = Result<T, ElGamalError>;

//=================================================================================================|

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ElGamalPublicKey {
    kappa: GroupElement,
}

impl ElGamalPublicKey {
    pub fn from_kappa(kappa: GroupElement) -> Self {
        Self { kappa }
    }

    //pub fn encrypt_to(&self, ...) -> ...

    /// Access to the [`GroupElement`] `kappa`.
    pub fn kappa(&self) -> &GroupElement {
        &self.kappa
    }
}

//-------------------------------------------------------------------------------------------------|

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct ElGamalSecretKey {
    /// Secret value.
    ///
    /// Ordinarily, an ElGamal system would think of this as a group element, but
    /// in ElectionGuard it is chosen as an element of the field.
    zeta: FieldElement,

    /// The public key for this secret key, if we happen to know it.
    pubkey_cache: RefCell<Option<Rc<ElGamalPublicKey>>>,
}

impl ElGamalSecretKey {
    /// Generates a new [`ElGamalSecretKey`] by picking a random [`FieldElement`].
    pub fn new_random(csrng: &dyn Csrng, field: &ScalarField) -> Self {
        Self {
            zeta: field.random_field_elem(csrng),
            pubkey_cache: RefCell::new(None),
        }
    }

    /// Access to the [`FieldElement`] `zeta`.
    pub fn zeta(&self) -> &FieldElement {
        &self.zeta
    }

    /// Gets or computes the [`ElGamalPublicKey`] for this [`ElGamalSecretKey`].
    pub fn public_key(&self, group: &Group) -> ElGamalResult<Rc<ElGamalPublicKey>> {
        {
            let pubkey_cache = self.pubkey_cache_try_borrow()?;
            if let Some(pubkey) = &*pubkey_cache {
                return Ok(pubkey.clone());
            }
        }

        let mut mut_pubkey_cache = self.pubkey_cache_try_borrow_mut()?;

        let pubkey = mut_pubkey_cache.get_or_insert_with(|| {
            let kappa = group.g_exp(&self.zeta);
            Rc::new(ElGamalPublicKey::from_kappa(kappa))
        });

        Ok(pubkey.clone())
    }

    pub(crate) fn pubkey_cache_try_borrow(
        &self,
    ) -> ElGamalResult<std::cell::Ref<'_, Option<Rc<ElGamalPublicKey>>>> {
        self.pubkey_cache
            .try_borrow()
            .map_err(|e| ElGamalError::TryBorrowSharedPubkeyCacheAlreadyMutablyInUse(e.to_string()))
    }

    pub(crate) fn pubkey_cache_try_borrow_mut(
        &self,
    ) -> ElGamalResult<std::cell::RefMut<'_, Option<Rc<ElGamalPublicKey>>>> {
        self.pubkey_cache.try_borrow_mut().map_err(|e| {
            ElGamalError::TryBorrowExclusivePubkeyCacheAlreadyMutablyInUse(e.to_string())
        })
    }
}

impl Zeroize for ElGamalSecretKey {
    fn zeroize(&mut self) {
        self.zeta.zeroize();
        if let Ok(mut mut_pubkey_cache) = self.pubkey_cache_try_borrow_mut() {
            *mut_pubkey_cache = None;
        } else {
            // Catch this in debug builds at least.
            debug_assert!(false);
        }
    }
}

impl Drop for ElGamalSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ElGamalSecretKey {}
