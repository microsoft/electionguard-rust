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
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use util::csrng::Csrng;

use crate::{
    errors::{EgError, EgResult},
    fixed_parameters::{FixedParametersTrait, FixedParametersTraitExt},
    resource::{ProduceResource, ProduceResourceExt},
    secret_coefficient::SecretCoefficient,
    serializable::SerializableCanonical,
};

//=================================================================================================|

/// A (not-yet-validated) vector of [`SecretCoefficient`]s.
///
/// Indices are 0-based and typically called `j`.
///
/// EGDS 2.1.0 eq. 7 pg. 22:
///
/// "Each guardian `G_i` in an election with a decryption threshold of `k` generates `k` secret
/// polynomial coefficients `a_{i,j}`, for `0 <= j < k`, by sampling them uniformly, at random
/// in `Z_q`"
#[allow(clippy::len_without_is_empty)]
pub trait SecretCoefficientsTrait {
    /// Returns the number of [`SecretCoefficient`]s.
    fn len(&self) -> usize;

    /// Provides access to the [`SecretCoefficient`]s as [`&[SecretCoefficient]`](std::slice).
    fn as_slice(&self) -> &[SecretCoefficient];

    /// Provides [`Iterator`] access to the [`SecretCoefficient`]s.
    fn iter(&self) -> impl Iterator<Item = &SecretCoefficient>;
}

/// Info for constructing a [`SecretCoefficients`] through validation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SecretCoefficientsInfo {
    /// The [`SecretCoefficient`]s.
    pub a_i_j: Vec<SecretCoefficient>,
}

impl SecretCoefficientsTrait for SecretCoefficientsInfo {
    fn len(&self) -> usize {
        self.a_i_j.len()
    }

    fn as_slice(&self) -> &[SecretCoefficient] {
        self.a_i_j.as_slice()
    }

    fn iter(&self) -> impl Iterator<Item = &SecretCoefficient> {
        self.a_i_j.iter()
    }
}

impl<'de> serde::Deserialize<'de> for SecretCoefficientsInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use strum::{IntoStaticStr, VariantNames};

        #[derive(serde::Deserialize, IntoStaticStr, VariantNames)]
        #[serde(field_identifier)]
        #[allow(non_camel_case_types)]
        enum Field {
            a_i_j,
        }

        struct SecretCoefficientsInfoVisitor;

        impl<'de> Visitor<'de> for SecretCoefficientsInfoVisitor {
            type Value = SecretCoefficientsInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("SecretCoefficientsInfo")
            }

            fn visit_map<MapAcc>(
                self,
                mut map: MapAcc,
            ) -> Result<SecretCoefficientsInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let Some((Field::a_i_j, a_i_j)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field(Field::a_i_j.into()));
                };

                Ok(SecretCoefficientsInfo { a_i_j })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("SecretCoefficients", FIELDS, SecretCoefficientsInfoVisitor)
    }
}

crate::impl_knows_friendly_type_name! { SecretCoefficientsInfo }

crate::impl_MayBeResource_for_non_Resource! { SecretCoefficientsInfo }

impl SerializableCanonical for SecretCoefficientsInfo {}

crate::impl_validatable_validated! {
    src: SecretCoefficientsInfo, produce_resource => EgResult<SecretCoefficients> {
        //? let election_parameters = produce_resource.election_parameters().await?.as_ref();
        //? let pre_voting_data = produce_resource.pre_voting_data().await?;
        //? let election_manifest = pre_voting_data.election_manifest();

        let SecretCoefficientsInfo {
            a_i_j,
        } = src;

        //----- Validate `a_i_j`.

        let k = produce_resource.varying_parameters().await?.k().as_quantity();
        let field = produce_resource.fixed_parameters().await?.field();

        if a_i_j.len() != k {
            let e = EgError::SecretCoefficientsIncorrectQuantity {
                qty_expected: k,
                qty_found: a_i_j.len(),
            };
            trace!("{e}");
            return Err(e);
        }

        //----- Construct the object from the validated data.

        let self_ = Self {
            a_i_j,
        };

        Ok(self_)
    }
}

impl From<SecretCoefficients> for SecretCoefficientsInfo {
    fn from(src: SecretCoefficients) -> Self {
        let SecretCoefficients { a_i_j } = src;
        Self { a_i_j }
    }
}

/// A (validated) vector of [`SecretCoefficient`]s.
///
/// Indices are 0-based and typically called `j`.
///
/// EGDS 2.1.0 eq. 7 pg. 22:
///
/// "Each guardian `G_i` in an election with a decryption threshold of `k` generates `k` secret
/// polynomial coefficients `a_{i,j}`, for `0 <= j < k`, by sampling them uniformly, at random
/// in `Z_q`"
#[derive(Debug, Clone, derive_more::From, serde::Serialize)]
pub struct SecretCoefficients {
    a_i_j: Vec<SecretCoefficient>,
}

impl SecretCoefficients {
    /// Generates a fresh [`SecretCoefficients`].
    ///
    /// The arguments are
    ///
    /// - `csrng` - secure randomness generator
    /// - `election_parameters` - the election parameters
    pub async fn generate(
        produce_resource: &(dyn ProduceResource + Send + Sync),
    ) -> EgResult<Self> {
        let csrng = produce_resource.csrng();
        let k = produce_resource
            .varying_parameters()
            .await?
            .k()
            .as_quantity();
        let fixed_parameters = produce_resource.fixed_parameters().await?;
        let field = fixed_parameters.field();

        let a_i_j: Vec<SecretCoefficient> =
            std::iter::repeat_with(|| SecretCoefficient::new_random(csrng, field))
                .take(k)
                .collect();

        Ok(SecretCoefficients { a_i_j })
    }
}

impl SecretCoefficientsTrait for SecretCoefficients {
    fn len(&self) -> usize {
        self.a_i_j.len()
    }

    fn as_slice(&self) -> &[SecretCoefficient] {
        self.a_i_j.as_slice()
    }

    fn iter(&self) -> impl Iterator<Item = &SecretCoefficient> {
        self.a_i_j.iter()
    }
}

crate::impl_knows_friendly_type_name! { SecretCoefficients }

crate::impl_MayBeResource_for_non_Resource! { SecretCoefficients }

impl SerializableCanonical for SecretCoefficients {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{Context, anyhow, bail, ensure};

    use util::{csrng::Csrng, vec1::Vec1};

    use crate::eg::Eg;

    use super::{SecretCoefficients, SecretCoefficientsInfo};

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "", //? TODO "eg::secret_coefficients::t::t1",
            );
            let eg = eg.as_ref();

            assert!(true); //? TODO
        });
    }
}
