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
#![allow(dead_code)]
//? TODO: Remove temp development code
//#![allow(unused_assignments)] //? TODO: Remove temp development code
//#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
//#![allow(unused_mut)] //? TODO: Remove temp development code
//#![allow(unused_variables)] //? TODO: Remove temp development code
//#![allow(unreachable_code)] //? TODO: Remove temp development code
//#![allow(non_camel_case_types)] //? TODO: Remove temp development code
//#![allow(non_snake_case)] //? TODO: Remove temp development code
//#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
//#![allow(noop_method_call)] //? TODO: Remove temp development code

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

//use anyhow::{anyhow, bail, ensure, Context, Result};
use downcast_rs::{DowncastSync, impl_downcast};
use either::Either;
//use futures_lite::future::{self, FutureExt};
//use hashbrown::HashMap;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use static_assertions::{assert_cfg, assert_impl_all, assert_obj_safe, const_assert};
#[allow(unused_imports)]
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::serializable::SerializableCanonical;

//=================================================================================================|

/// Selection and complete specification of a hash-trimming function `Ω`.
///
/// EGDS 2.1.0 Sec 4 pg. 57
/// EGDS 2.1.0 Sec 4.6 pg. 68
///
/// "Pre-Encrypted Ballots (Optional)"
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    strum_macros::Display
)]
pub enum HashTrimmingFnOmega {
    /// The `Two Hex Characters` hash-trimming function `Ω`.
    ///
    /// EGDS 2.1.0 Sec 4.6 pg. 68:
    ///
    /// - `Ω_1(x)` final byte of `x` expressed as two hexadecimal characters.
    #[strum(to_string = "two hex characters")]
    TwoHexCharacters,

    /// The `Four Hex Characters` hash-trimming function `Ω`.
    ///
    /// EGDS 2.1.0 Sec 4.6 pg. 68:
    ///
    /// - `Ω_2(x)` final two bytes of `x` expressed as four hexadecimal characters.
    #[strum(to_string = "four hex characters")]
    FourHexCharacters,

    /// The `Letter-Digit` hash-trimming function `Ω`.
    ///
    /// EGDS 2.1.0 Sec 4.6 pg. 68:
    ///
    /// - `Ω_3(x)` final byte of `x` expressed as a letter followed by a digit with
    ///   `{0,1,...,255}` mapping to `{A0,A1,...,A9,B0,B1,...B9,...,Z0,Z1,...,Z5}`.
    #[strum(to_string = "letter-digit")]
    LetterDigit,

    /// The `Digit-Letter` hash-trimming function `Ω`.
    ///
    /// EGDS 2.1.0 Sec 4.6 pg. 68:
    ///
    /// - `Ω_4(x)` final byte of `x` expressed as a digit followed by a letter with
    ///   `{0,1,...,255}` mapping to `{0A,0B,...,0Z,1A,1B,...1Z,...,9A,9B,...,9V}`.
    #[strum(to_string = "letter-digit")]
    DigitLetter,

    /// The `Number: 0-255` hash-trimming function `Ω`.
    ///
    /// EGDS 2.1.0 Sec 4.6 pg. 68:
    ///
    /// - `Ω_5(x)` final byte of `x` expressed as a number with `{0,1,...,255}` mapping to
    ///   `{0,1,...,255}` using the identity function.
    #[strum(to_string = "number 0-255")]
    #[allow(non_camel_case_types)]
    Number_0_255,

    /// The `Number: 1-256` hash-trimming function `Ω`.
    ///
    /// EGDS 2.1.0 Sec 4.6 pg. 68:
    ///
    /// - `Ω_6(x)` final byte of `x` expressed as a number with `{0,1,...,255}` mapping to
    ///   `{1,2,...,256}` by adding 1.
    #[strum(to_string = "number 1-256")]
    #[allow(non_camel_case_types)]
    Number_1_256,

    /// The `Number: 100-355` hash-trimming function `Ω`.
    ///
    /// EGDS 2.1.0 Sec 4.6 pg. 68:
    ///
    /// - `Ω_7(x)` final byte of `x` expressed as a number with `{0,1,...,255}` mapping to
    ///   `{100,101,...,355}` by adding 100.
    #[strum(to_string = "number 100-355")]
    #[allow(non_camel_case_types)]
    Number_100_355,

    /// The `Number: 101-356` hash-trimming function `Ω`.
    ///
    /// EGDS 2.1.0 Sec 4.6 pg. 68:
    ///
    /// - `Ω_8(x)` final byte of `x` expressed as a number with `{0,1,...,255}` mapping to
    ///   `{101,102,...,356}` by adding 101.
    #[strum(to_string = "number 101-356")]
    #[allow(non_camel_case_types)]
    Number_101_356,

    /// Configuration of a vendor-supplied hash-trimming function `Ω`.
    ///
    /// EGDS 2.1.0 Sec 4.6 pg. 68:
    ///
    /// - "To allow vendors and jurisdictions to present distinct formats to their voters, the
    ///   details of the hash-trimming function that produces short codes from full-sized hashes
    ///   are not explicitly provided. However, to facilitate verification, a variety of possible
    ///   hash-trimming functions are pre-specified here."
    #[strum(to_string = "other {0}")]
    Other(serde_json::Value),
}

//=================================================================================================|

#[allow(non_camel_case_types)]
pub type BoxPreencryptedBallotsConfigInfo_or_BoxPreencryptedBallotsConfig =
    Either<Box<PreencryptedBallotsConfigInfo>, Box<PreencryptedBallotsConfig>>;

#[allow(non_camel_case_types)]
pub type ArcPreencryptedBallotsConfigInfo_or_ArcPreencryptedBallotsConfig =
    Either<Arc<PreencryptedBallotsConfigInfo>, Arc<PreencryptedBallotsConfig>>;

//-------------------------------------------------------------------------------------------------|

/// Element access and other operations common to [`PreencryptedBallotsConfigInfo`] and [`PreencryptedBallotsConfig`].
#[async_trait::async_trait(?Send)]
pub trait PreencryptedBallotsConfigTrait: DowncastSync {
    /// Complete specifiction of the hash-trimming function `Ω`.
    ///
    /// EGDS 2.1.0 Sec 4 pg. 57
    /// EGDS 2.1.0 Sec 4.6 pg. 68
    ///
    /// "Pre-Encrypted Ballots (Optional)"
    fn hash_trimming_fn_omega(&self) -> &HashTrimmingFnOmega;
}

assert_obj_safe!(PreencryptedBallotsConfigTrait);

impl_downcast!(sync PreencryptedBallotsConfigTrait);

//-------------------------------------------------------------------------------------------------|

/// Info for constructing a [`PreencryptedBallotsConfig`] through validation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct PreencryptedBallotsConfigInfo {
    /// Complete specifiction of the hash-trimming function `Ω`.
    hash_trimming_fn_omega: HashTrimmingFnOmega,
}

impl PreencryptedBallotsConfigTrait for PreencryptedBallotsConfigInfo {
    fn hash_trimming_fn_omega(&self) -> &HashTrimmingFnOmega {
        &self.hash_trimming_fn_omega
    }
}

impl<'de> serde::Deserialize<'de> for PreencryptedBallotsConfigInfo {
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
            hash_trimming_fn_omega,
        }

        struct PreencryptedBallotsConfigInfoVisitor;

        impl<'de> Visitor<'de> for PreencryptedBallotsConfigInfoVisitor {
            type Value = PreencryptedBallotsConfigInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("PreencryptedBallotsConfigInfo")
            }

            fn visit_map<MapAcc>(
                self,
                mut map: MapAcc,
            ) -> Result<PreencryptedBallotsConfigInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let Some((Field::hash_trimming_fn_omega, hash_trimming_fn_omega)) =
                    map.next_entry()?
                else {
                    return Err(MapAcc::Error::missing_field(
                        Field::hash_trimming_fn_omega.into(),
                    ));
                };

                Ok(PreencryptedBallotsConfigInfo {
                    hash_trimming_fn_omega,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct(
            "PreencryptedBallotsConfig",
            FIELDS,
            PreencryptedBallotsConfigInfoVisitor,
        )
    }
}

crate::impl_knows_friendly_type_name! { PreencryptedBallotsConfigInfo }

//? crate::impl_Resource_for_simple_ElectionDataObjectId_info_type! { PreencryptedBallotsConfigInfo, PreencryptedBallotsConfig }
//? alternatively:
crate::impl_MayBeResource_for_non_Resource! { PreencryptedBallotsConfigInfo }

impl SerializableCanonical for PreencryptedBallotsConfigInfo {}

crate::impl_validatable_validated! {
    src: PreencryptedBallotsConfigInfo, produce_resource => EgResult<PreencryptedBallotsConfig> {
        //? let election_parameters = produce_resource.election_parameters().await?.as_ref();
        //? let pre_voting_data = produce_resource.pre_voting_data().await?;
        //? let election_manifest = pre_voting_data.election_manifest();

        let PreencryptedBallotsConfigInfo {
            hash_trimming_fn_omega,
        } = src;

        //----- Validate `hash_trimming_fn_omega`.

        //? TODO: validate

        //----- Construct the object from the validated data.

        let self_ = Self {
            hash_trimming_fn_omega,
        };

        Ok(self_)
    }
}

impl From<PreencryptedBallotsConfig> for PreencryptedBallotsConfigInfo {
    fn from(src: PreencryptedBallotsConfig) -> Self {
        let PreencryptedBallotsConfig {
            hash_trimming_fn_omega,
        } = src;

        Self {
            hash_trimming_fn_omega,
        }
    }
}

/// A validated [`PreencryptedBallotsConfig`].
#[derive(Debug, Clone, derive_more::From, serde::Serialize)]
pub struct PreencryptedBallotsConfig {
    hash_trimming_fn_omega: HashTrimmingFnOmega,
}

impl PreencryptedBallotsConfigTrait for PreencryptedBallotsConfig {
    fn hash_trimming_fn_omega(&self) -> &HashTrimmingFnOmega {
        &self.hash_trimming_fn_omega
    }
}

crate::impl_knows_friendly_type_name! { PreencryptedBallotsConfig }

//?crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { PreencryptedBallotsConfig, PreencryptedBallotsConfig }
crate::impl_MayBeResource_for_non_Resource! { PreencryptedBallotsConfig }

impl SerializableCanonical for PreencryptedBallotsConfig {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{Context, anyhow, bail, ensure};

    use util::{csrng::Csrng, vec1::Vec1};

    use crate::eg::Eg;

    use super::{PreencryptedBallotsConfig, PreencryptedBallotsConfigInfo};

    #[test_log::test]
    #[allow(unused_variables)] //? TODO: Remove temp development code
    fn t1() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "", //? TODO "eg::preencrypted_ballots::t::t1",
            );
            let eg = eg.as_ref();

            assert!(true); //? TODO
        });
    }
}
