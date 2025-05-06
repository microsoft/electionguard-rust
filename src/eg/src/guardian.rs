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

use util::index::Index;

use crate::{
    errors::{EgError, EgResult},
    key::{AsymmetricKeyPart, KeyPurpose},
    label::{LabeledItem, validate_label},
    resource::{ElectionDataObjectId, Resource, ResourceFormat, ResourceId, ResourceIdFormat},
    serializable::SerializableCanonical,
};

//=================================================================================================|

#[doc(hidden)]
/// Tag used to specialize [`Index`] for Guardian indices.
pub struct GuardianIndexTag;

/// Guardian `i`.
///
/// Used for:
///
/// - [`VaryingParameters::n`](crate::varying_parameters::VaryingParameters::n), `1` <= [`n`](crate::varying_parameters::VaryingParameters::n) < `2^31`.
/// - [`VaryingParameters::k`](crate::varying_parameters::VaryingParameters::k), `1` <= [`k`](crate::varying_parameters::VaryingParameters::k) <= [`n`](crate::varying_parameters::VaryingParameters::n).
/// - [`GuardianSecretKey::i`](crate::guardian_secret_key::GuardianSecretKey::i), `1` <= [`i`](crate::guardian_secret_key::GuardianSecretKey::i) <= [`n`](crate::varying_parameters::VaryingParameters::n).
/// - [`GuardianPublicKey::i`](crate::guardian_public_key::GuardianPublicKey::i), `1` <= [`i`](crate::guardian_public_key::GuardianPublicKey::i) <= [`n`](crate::varying_parameters::VaryingParameters::n).
///
pub type GuardianIndex = Index<GuardianIndexTag>;

/// Attempts to convert guardian_ix value into guardian_ix GuardianIndex.
///
/// Just like [`TryInto`](std::convert::TryInto), but this gives you an [`EgResult`].
pub fn try_into_guardian_index<T>(ix1: T) -> EgResult<GuardianIndex>
where
    T: TryInto<GuardianIndex>,
    <T as TryInto<GuardianIndex>>::Error: Into<EgError>,
{
    TryInto::<GuardianIndex>::try_into(ix1).map_err(Into::<EgError>::into)
}

//=================================================================================================|

//? TODO I think this goes away?
/// Identifies guardian_ix part of guardian_ix Guardian key. E.g. Guardian [`1`](GuardianIndex)'s
/// [`Vote Encryption`](GuardianKeyPurpose::Encrypt_Ballot_NumericalVotesAndAdditionalDataFields)
/// [`Secret`](AsymmetricKeyPart::Secret) Key.
#[derive(
    Clone,
    Copy,
    Debug,
    derive_more::Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize
)]
#[display("Guardian {guardian_ix}, {key_purpose}, {asymmetric_key_part}")]
pub struct GuardianKeyPartId {
    /// Guardian index, `1` <= `guardian_ix` <= [`n`](crate::varying_parameters::VaryingParameters::n).
    pub guardian_ix: GuardianIndex,

    /// Key purpose.
    pub key_purpose: KeyPurpose,

    /// Which part of the asymmetric key, i.e., [`Public`](AsymmetricKeyPart::Public) or
    /// [`Secret`](AsymmetricKeyPart::Secret).
    pub asymmetric_key_part: AsymmetricKeyPart,
}

//=================================================================================================|

#[allow(non_camel_case_types)]
pub type BoxGuardianInfo_or_BoxGuardian = Either<Box<GuardianInfo>, Box<Guardian>>;

#[allow(non_camel_case_types)]
pub type ArcGuardianInfo_or_ArcGuardian = Either<Arc<GuardianInfo>, Arc<Guardian>>;

//-------------------------------------------------------------------------------------------------|

/// Element access and other operations common to [`GuardianInfo`] and [`Guardian`].
#[async_trait::async_trait(?Send)]
pub trait GuardianTrait: DowncastSync {
    /// Guardian index number.
    fn guardian_ix(&self) -> GuardianIndex;

    /// Data item label.
    fn label(&self) -> &String;

    /// Implement this to return one of:
    ///
    /// - [`ConcreteType`](ResourceFormat::ConcreteType), or
    /// - [`ValidElectionDataObject`](ResourceFormat::ValidElectionDataObject)
    fn format_owned(&self) -> ResourceFormat;

    fn ridfmt_owned(&self) -> ResourceIdFormat {
        ResourceIdFormat {
            rid: self.rid_owned(),
            fmt: self.format_owned(),
        }
    }

    fn rid_owned(&self) -> ResourceId {
        let edoid = ElectionDataObjectId::Guardian(self.guardian_ix());
        ResourceId::ElectionDataObject(edoid)
    }
}

assert_obj_safe!(GuardianTrait);

impl_downcast!(sync GuardianTrait);

//-------------------------------------------------------------------------------------------------|

/// Info for constructing guardian_ix [`Guardian`] through validation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct GuardianInfo {
    /// Guardian index number.
    pub guardian_ix: GuardianIndex,

    /// The label for this [`Guardian`].
    pub label: String,
}

impl GuardianTrait for GuardianInfo {
    fn guardian_ix(&self) -> GuardianIndex {
        self.guardian_ix
    }
    fn label(&self) -> &String {
        &self.label
    }
    fn format_owned(&self) -> ResourceFormat {
        ResourceFormat::ConcreteType
    }
}

impl<'de> serde::Deserialize<'de> for GuardianInfo {
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
            guardian_ix,
            label,
        }

        struct GuardianInfoVisitor;

        impl<'de> Visitor<'de> for GuardianInfoVisitor {
            type Value = GuardianInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("GuardianInfo")
            }

            fn visit_map<MapAcc>(self, mut map: MapAcc) -> Result<GuardianInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let Some((Field::guardian_ix, guardian_ix)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field(Field::guardian_ix.into()));
                };

                let Some((Field::label, label)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field(Field::label.into()));
                };

                Ok(GuardianInfo { guardian_ix, label })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("Guardian", FIELDS, GuardianInfoVisitor)
    }
}

crate::impl_knows_friendly_type_name! { GuardianInfo }

impl Resource for GuardianInfo {
    fn ridfmt(&self) -> Cow<'_, ResourceIdFormat> {
        Cow::Owned(self.ridfmt_owned())
    }
    fn rid(&self) -> Cow<'_, ResourceId> {
        Cow::Owned(self.rid_owned())
    }
    fn format(&self) -> Cow<'_, ResourceFormat> {
        Cow::Owned(self.format_owned())
    }
}

impl SerializableCanonical for GuardianInfo {}

crate::impl_validatable_validated! {
    src: GuardianInfo, produce_resource => EgResult<Guardian> {
        let GuardianInfo {
            guardian_ix,
            label,
        } = src;

        //----- Validate `guardian_ix`.

        // Type [`GuardianIndex`] enforces its own constraints.

        //----- Validate `label`.

        validate_label(label.as_str(), LabeledItem::Guardian(guardian_ix))?;

        //----- Construct the object from the validated data.

        let self_ = Self {
            guardian_ix,
            label,
        };

        Ok(self_)
    }
}

impl From<Guardian> for GuardianInfo {
    fn from(src: Guardian) -> Self {
        let Guardian { guardian_ix, label } = src;

        Self { guardian_ix, label }
    }
}

/// A validated [`Guardian`].
#[derive(Debug, Clone, derive_more::From, serde::Serialize)]
pub struct Guardian {
    guardian_ix: GuardianIndex,
    label: String,
}

impl GuardianTrait for Guardian {
    fn guardian_ix(&self) -> GuardianIndex {
        self.guardian_ix
    }
    fn label(&self) -> &String {
        &self.label
    }
    fn format_owned(&self) -> ResourceFormat {
        ResourceFormat::ValidElectionDataObject
    }
}

crate::impl_knows_friendly_type_name! { Guardian }

impl Resource for Guardian {
    fn ridfmt(&self) -> Cow<'_, ResourceIdFormat> {
        Cow::Owned(self.ridfmt_owned())
    }
    fn rid(&self) -> Cow<'_, ResourceId> {
        Cow::Owned(self.rid_owned())
    }
    fn format(&self) -> Cow<'_, ResourceFormat> {
        Cow::Owned(self.format_owned())
    }
}

impl SerializableCanonical for Guardian {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(unused_imports)] //? TODO: Remove temp development code
mod t {
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

    use super::{Guardian, GuardianInfo};

    async fn test_guardian_label(guardian_label: &str) -> EgResult<()> {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(format!(
            "eg::guardian::t::test_guardian_label: {guardian_label:?}"
        ));
        let eg = eg.as_ref();

        let guardian_jv = json!({ "guardian_ix": 1, "label": guardian_label });

        let guardian_js = serde_json::to_string_pretty(&guardian_jv).unwrap();

        let guardian_info = GuardianInfo::from_json_str_validatable(guardian_js.as_str()).unwrap();

        Guardian::try_validate_from(guardian_info, eg).map(|_| ())
    }

    #[test_log::test]
    fn t1() {
        async_global_executor::block_on(async {
            // EGRI accepts Guardian labels composed of printable characters and (internal, non-contiguous) 0x20 space characters

            assert_ron_snapshot!(test_guardian_label(
                    "A"
                ).await,
                @"Ok(())");

            assert_ron_snapshot!(test_guardian_label(
                    "Prof. Sébastian Moonglôw, Silvërspîre County Register of Deeds"
                ).await,
                @"Ok(())");

            assert_ron_snapshot!(test_guardian_label(
                    "Tïtus Stormforge, Librarian-in-Chief of Smoothstone County"
                ).await,
                @"Ok(())");
        });
    }

    #[test_log::test]
    fn t2() {
        async_global_executor::block_on(async {
            // EGRI rejects Guardian labels that contain line break characters
            assert_ron_snapshot!(test_guardian_label(
                    "Guardian\nlabel\nthat contains line break characters"
                ).await,
                @r#"
            Err(LabelError(NotAllowedChar(CharNotAllowedInText(
              labeled_item: Guardian(1),
              char_ix1: 9,
              byte_offset: 8,
              unicode_property: Control,
              unicode_version: (16, 0, 0),
            ))))
            "#);

            // EGRI rejects Guardian labels that have leading or trailing whitespace
            assert_ron_snapshot!(test_guardian_label(
                    " Guardian label that has leading whitespace"
                ).await,
                @r#"
            Err(LabelError(LeadingOrTrailingWhitespace((Leading, CharNotAllowedInText(
              labeled_item: Guardian(1),
              char_ix1: 1,
              byte_offset: 0,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            )))))
            "#);

            assert_ron_snapshot!(test_guardian_label(
                    "Guardian label that has trailing whitespace "
                ).await,
                @r#"
            Err(LabelError(LeadingOrTrailingWhitespace((Trailing, CharNotAllowedInText(
              labeled_item: Guardian(1),
              char_ix1: 44,
              byte_offset: 43,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            )))))
            "#);

            // EGRI rejects Guardian labels that contain contiguous sequences of whitespace other than a single 0x20 space
            assert_ron_snapshot!(test_guardian_label(
                    "Guardian  label that contains contiguous sequences of whitespace"
                ).await,
                @r#"
            Err(LabelError(ContiguousWhitespace(CharNotAllowedInText(
              labeled_item: Guardian(1),
              char_ix1: 10,
              byte_offset: 9,
              unicode_property: Whitespace,
              unicode_version: (16, 0, 0),
            ))))
            "#);

            // EGRI rejects Guardian labels that contain special characters (Unicode Category Cc, Cf, Zs, Zl, Zp, or Cs)
            // 0x002028 - LINE SEPARATOR - 'Zl'
            assert_ron_snapshot!(test_guardian_label(
                    "Guardian\u{002028}label that contains a special character"
                ).await,
                @r#"
            Err(LabelError(NotAllowedChar(CharNotAllowedInText(
              labeled_item: Guardian(1),
              char_ix1: 9,
              byte_offset: 8,
              unicode_property: LineSeparator,
              unicode_version: (16, 0, 0),
            ))))
            "#);

            // EGRI rejects Guardian labels having no printable characters
            assert_ron_snapshot!(test_guardian_label(
                    ""
                ).await,
                @"Err(LabelError(NoPossiblyPrintableCharacters(Guardian(1))))");

            assert_ron_snapshot!(test_guardian_label(
                    "\u{00200C}"
                ).await,
                @"Err(LabelError(NoPossiblyPrintableCharacters(Guardian(1))))");

            //? TODO EGRI rejects Guardian labels that decode to a Unicode malformed surrogate pair (Unicode Category Cs). See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603)
            //? TODO
        });
    }
}
