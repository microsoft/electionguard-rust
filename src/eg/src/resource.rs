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
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::borrow::Cow;
//use std::collections::HashSet;
//use std::io::{BufRead, Cursor};
//use std::path::{Path, PathBuf};
use std::rc::Rc;

//use std::str::FromStr;
//use std::sync::OnceLock;

//use anyhow::{anyhow, bail, ensure, Context, Result};
use downcast_rs::Downcast;
//use either::Either;
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};
//use rand::{distr::Uniform, Rng, RngCore};
use serde::{Deserialize, Serialize};
use util::abbreviation::Abbreviation;

/// Re-export [`ResourceId`] and related names because they're so essential.
pub use crate::resource_id::{ElectionDataObjectId, ResourceFormat, ResourceId, ResourceIdFormat};
use crate::{
    eg::Eg,
    errors::EgResult,
    guardian::{GuardianKeyId, GuardianKeyPurpose},
    resource_path::ResourceNamespacePath,
    resource_producer::ResourceProductionResult,
    serializable::{SerializableCanonical, SerializablePretty},
};

//=================================================================================================|

/// A [`Resource`] is info available to processing.
///
/// Typically variants correspond to file paths, most commonly a serialized representation of
/// an [`ElectionDataObject`].
///
/// Often it is a temporary used create an [`ElectionDataObject`] through [validation](
/// crate::validatableValidated), but they can be other data se well.
///
/// For example, an `ElectionDataObject` type may be serialized to a file, but may not be
/// [deserialized](serde::Deserialize) directly. Instead, the corresponding `Resource` is
/// loaded, and the `ElectionDataObject` created through validation.
///
pub trait Resource:
    Downcast + std::fmt::Debug + erased_serde::Serialize + SerializableCanonical + SerializablePretty
{
    /// Returns the [`ResourceIdFormat`] of this resource.
    fn ridfmt(&self) -> &ResourceIdFormat;

    /// Returns the [`ResourceId`] of this resource.
    fn rid(&self) -> &ResourceId {
        &self.ridfmt().rid
    }

    /// Returns the [`ResourceFormat`] of this resource.
    fn format(&self) -> &ResourceFormat {
        &self.ridfmt().fmt
    }

    /// Returns the [`ElectionDataObjectId`] of this resource, if it happens to represent
    /// an [`ElectionDataObject`].
    fn edoid_opt(&self) -> Option<&ElectionDataObjectId> {
        use ResourceId::*;
        match self.rid() {
            ElectionDataObject(edoid) => Some(edoid),
            _ => None,
        }
    }

    /// Returns the resource as a slice of bytes, perhaps suitable for deserialization.
    fn as_slice_bytes(&self) -> Option<&[u8]> {
        None
    }

    /*
    /// Returns the [`std::io::Read`], if the resource supports it.
    /// This should be buffered under the hood.
    fn as_stdio_read_opt(&mut self) -> Option<&dyn std::io::Read> {
        None
    }
    // */
}

downcast_rs::impl_downcast!(Resource);

erased_serde::serialize_trait_object!(Resource);

//=================================================================================================|

/// Trait for types that can return a ref to a static ResourceIdFormat.
pub trait HasStaticResourceIdFormat
//    Downcast
//+ std::fmt::Debug
//+ erased_serde::Serialize
//+ SerializableCanonical + SerializablePretty
{
    fn static_ridfmt(&self) -> &'static ResourceIdFormat;
}

impl<T> Resource for T
where
    T: HasStaticResourceIdFormat
        + Downcast
        + std::fmt::Debug
        + erased_serde::Serialize
        + SerializableCanonical
        + SerializablePretty
        + ?Sized,
{
    fn ridfmt(&self) -> &ResourceIdFormat {
        Self::static_ridfmt(self)
    }
}

//=================================================================================================|

/// Trait for types that could possibly implement the [`Resource`] trait.
pub trait MayBeResource {
    /// May return [`&self`](self) as a [`&dyn Resource`](Resource).
    fn opt_as_resource(&self) -> Option<&dyn Resource>;

    /// May return [`&mut self`](self) as a [`&mut dyn Resource`](Resource).
    fn opt_as_resource_mut(&mut self) -> Option<&mut dyn Resource>;
}

impl<T> MayBeResource for T
where
    T: Resource,
{
    fn opt_as_resource(&self) -> Option<&dyn Resource> {
        Some(self)
    }

    fn opt_as_resource_mut(&mut self) -> Option<&mut dyn Resource> {
        Some(self)
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use anyhow::{anyhow, bail, ensure, Context, Result};
    use insta::assert_ron_snapshot;

    use super::*;
    use crate::guardian::{AsymmetricKeyPart, GuardianIndex, GuardianKeyPurpose};

    #[test]
    fn edoid() {
        use ElectionDataObjectId::*;
        use GuardianKeyPurpose::*;
        assert_ron_snapshot!(FixedParameters, @"FixedParameters");
        assert_ron_snapshot!(VaryingParameters, @"VaryingParameters");
        assert_ron_snapshot!(ElectionParameters, @"ElectionParameters");
        assert_ron_snapshot!(ElectionManifest, @"ElectionManifest");
        assert_ron_snapshot!(Hashes, @"Hashes");
        assert_ron_snapshot!(GuardianKeyPart(GuardianKeyId {
            guardian_ix: GuardianIndex::one(),
            key_purpose: Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
            asymmetric_key_part: AsymmetricKeyPart::Secret,
        }), @r#"
        GuardianKeyPart(GuardianKeyId(
          guardian_ix: 1,
          key_purpose: Encrypt_Ballot_NumericalVotesAndAdditionalDataFields,
          asymmetric_key_part: Secret,
        ))
        "#);
        assert_ron_snapshot!(JointPublicKey(Encrypt_Ballot_AdditionalFreeFormData), @"JointPublicKey(Encrypt_Ballot_AdditionalFreeFormData)");
        assert_ron_snapshot!(ExtendedBaseHash, @"ExtendedBaseHash");
        assert_ron_snapshot!(PreVotingData, @"PreVotingData");

        #[cfg(feature = "eg-allow-test-data-generation")]
        assert_ron_snapshot!(GeneratedTestDataVoterSelections(
            crate::hash::HValue::from(std::array::from_fn(|ix| ix as u8 + 0x70))
        ), @r#"GeneratedTestDataVoterSelections("707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F")"#);
    }

    #[test]
    fn rid() {
        use ElectionDataObjectId::*;
        use ResourceId::*;

        assert_ron_snapshot!(
            ElectionGuardDesignSpecificationVersion,
            @"ElectionGuardDesignSpecificationVersion");

        assert_ron_snapshot!(
            ElectionDataObject(FixedParameters),
            @"ElectionDataObject(FixedParameters)");

        assert_ron_snapshot!(ElectionDataObject(FixedParameters).try_figure_namespace_path(), @"None");
    }
}
