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

#[allow(non_camel_case_types)]
pub type BoxEdoTemplateSimpleInfo_or_BoxEdoTemplateSimple =
    Either<Box<EdoTemplateSimpleInfo>, Box<EdoTemplateSimple>>;

#[allow(non_camel_case_types)]
pub type ArcEdoTemplateSimpleInfo_or_ArcEdoTemplateSimple =
    Either<Arc<EdoTemplateSimpleInfo>, Arc<EdoTemplateSimple>>;

//-------------------------------------------------------------------------------------------------|

/// Element access and other operations common to [`EdoTemplateSimpleInfo`] and [`EdoTemplateSimple`].
#[async_trait::async_trait(?Send)]
pub trait EdoTemplateSimpleTrait: DowncastSync {
    /// Data item a.
    fn data_a(&self) -> &String;

    /// Data item b.
    fn data_b(&self) -> &u32;
}

assert_obj_safe!(EdoTemplateSimpleTrait);

impl_downcast!(sync EdoTemplateSimpleTrait);

//-------------------------------------------------------------------------------------------------|

/// Info for constructing a [`EdoTemplateSimple`] through validation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct EdoTemplateSimpleInfo {
    /// Data item a.
    pub data_a: String,

    /// Data item b.
    pub data_b: u32,
}

impl EdoTemplateSimpleTrait for EdoTemplateSimpleInfo {
    fn data_a(&self) -> &String {
        &self.data_a
    }
    fn data_b(&self) -> &u32 {
        &self.data_b
    }
}

impl<'de> serde::Deserialize<'de> for EdoTemplateSimpleInfo {
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
            a,
            b,
        }

        struct EdoTemplateSimpleInfoVisitor;

        impl<'de> Visitor<'de> for EdoTemplateSimpleInfoVisitor {
            type Value = EdoTemplateSimpleInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("EdoTemplateSimpleInfo")
            }

            fn visit_map<MapAcc>(
                self,
                mut map: MapAcc,
            ) -> Result<EdoTemplateSimpleInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let Some((Field::a, a)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field(Field::a.into()));
                };

                let Some((Field::b, b)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field(Field::b.into()));
                };

                Ok(EdoTemplateSimpleInfo {
                    data_a: a,
                    data_b: b,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("EdoTemplateSimple", FIELDS, EdoTemplateSimpleInfoVisitor)
    }
}

crate::impl_knows_friendly_type_name! { EdoTemplateSimpleInfo }

crate::impl_Resource_for_simple_ElectionDataObjectId_info_type! { EdoTemplateSimpleInfo, EdoTemplateSimple }
//? alternatively: crate::impl_MayBeResource_for_non_Resource! { EdoTemplateSimpleInfo }

impl SerializableCanonical for EdoTemplateSimpleInfo {}

crate::impl_validatable_validated! {
    src: EdoTemplateSimpleInfo, produce_resource => EgResult<EdoTemplateSimple> {
        //? let election_parameters = produce_resource.election_parameters().await?.as_ref();
        //? let pre_voting_data = produce_resource.pre_voting_data().await?;
        //? let election_manifest = pre_voting_data.election_manifest();

        let EdoTemplateSimpleInfo {
            data_a,
            data_b,
        } = src;

        //----- Validate `a`.

        //? TODO: validate

        //----- Validate `b`.

        //? TODO: validate

        //----- Construct the object from the validated data.

        let self_ = Self {
            data_a,
            data_b,
        };

        Ok(self_)
    }
}

impl From<EdoTemplateSimple> for EdoTemplateSimpleInfo {
    fn from(src: EdoTemplateSimple) -> Self {
        let EdoTemplateSimple { data_a, data_b } = src;

        Self { data_a, data_b }
    }
}

/// A validated [`EdoTemplateSimple`].
#[derive(Debug, Clone, derive_more::From, serde::Serialize)]
pub struct EdoTemplateSimple {
    data_a: String,
    data_b: u32,
}

impl EdoTemplateSimpleTrait for EdoTemplateSimple {
    fn data_a(&self) -> &String {
        &self.data_a
    }
    fn data_b(&self) -> &u32 {
        &self.data_b
    }
}

crate::impl_knows_friendly_type_name! { EdoTemplateSimple }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { EdoTemplateSimple, EdoTemplateSimple }
//? alternatively: crate::impl_MayBeResource_for_non_Resource! { EdoTemplateSimple }

impl SerializableCanonical for EdoTemplateSimple {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(unused_imports)] //? TODO: Remove temp development code
mod t {
    use anyhow::{Context, anyhow, bail, ensure};
    use insta::assert_ron_snapshot;
    use serde_json::json;

    //
    use util::{csrng::Csrng, vec1::Vec1};

    use crate::{
        eg::Eg,
        errors::{EgError, EgResult},
        loadable::{LoadableFromStdIoReadValidatable, LoadableFromStdIoReadValidated},
        serializable::{SerializableCanonical, SerializablePretty},
        validatable::{Validatable, Validated},
    };

    use super::{EdoTemplateSimple, EdoTemplateSimpleInfo};

    #[test_log::test]
    #[allow(unused_variables)] //? TODO: Remove temp development code
    fn t1() {
        async_global_executor::block_on(async {
            let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
                "", //? TODO "eg::edo_template::t::t1",
            );
            let eg = eg.as_ref();

            assert!(true); //? TODO
        });
    }
}
