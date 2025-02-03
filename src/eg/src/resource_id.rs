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
    borrow::Cow,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //io::{BufRead, Cursor},
    //path::{Path, PathBuf},
    //rc::Rc,
    //str::FromStr,
    //sync::OnceLock,
};

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
//use static_assertions::assert_obj_safe;
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
use util::abbreviation::Abbreviation;

use crate::{
    //eg::Eg,
    //errors::EgResult,
    guardian::{GuardianKeyId, GuardianKeyPurpose},
    resource_path::ResourceNamespacePath,
};

//=================================================================================================|

/// Identifies an [`ElectionDataObject`].
///
#[derive(
    Clone, Debug,
    derive_more::Display,
    PartialEq, Eq,
    PartialOrd, Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize,
    //Valuable,
)]
pub enum ElectionDataObjectId {
    FixedParameters,
    VaryingParameters,
    ElectionParameters,

    /// Defines a [`BallotStyle`]. Part of the [`ElectionManifest`].
    BallotStyle,

    /// Part of the [`ElectionManifest`] that specifies which data is to be included in the
    /// `S_device` string, which is hashed to produce the [`VotingDeviceInformationHash`],
    /// `H_DI`. See [`VotingDeviceInformationSpec`](crate::voting_device::VotingDeviceInformationSpec).
    VotingDeviceInformationSpec,

    /// [`ElectionManifest`](crate::election_manifest::ElectionManifest)
    ElectionManifest,

    /// [`Hashes`](crate::hashes::Hashes)
    Hashes,

    /// A guardian key (either a public or secret part), identified by the [`GuardianKeyId`].
    #[display("GuardianKeyPart({_0})")]
    GuardianKeyPart(GuardianKeyId),

    ///? TODO Consider making this two separate identifiers, as there's no joint key for `kappa`.
    #[display("JointPublicKey({_0})")]
    JointPublicKey(GuardianKeyPurpose),

    /// `H_E` [`ExtendedBaseHash`](crate::extended_base_hash::ExtendedBaseHash)
    ///
    /// EGDS 2.1.0 sec. 3.2.3 eq. 30 pg. 28
    ExtendedBaseHash,

    //? TODO remove this
    PreVotingData,

    #[cfg(feature = "eg-allow-test-data-generation")]
    /// Voter selections randomly generated from the hash of a seed string in compliance with the ElectionManifest.
    GeneratedTestDataVoterSelections(crate::hash::HValue),

    /// The election tallies.
    ElectionTallies,
}

impl ElectionDataObjectId {
    /// Converts the ElectionDataObjectId to a ResourceIdFormat specification requesting the
    /// corresponding not-yet-validated info type.
    pub const fn info_type_ridfmt(self) -> ResourceIdFormat {
        ResourceIdFormat {
            rid: ResourceId::ElectionDataObject(self),
            fmt: ResourceFormat::ConcreteType,
        }
    }

    /// Converts the ElectionDataObjectId to a ResourceIdFormat specification requesting the
    /// corresponding validated EDO.
    pub const fn validated_type_ridfmt(self) -> ResourceIdFormat {
        ResourceIdFormat {
            rid: ResourceId::ElectionDataObject(self),
            fmt: ResourceFormat::ValidatedElectionDataObject,
        }
    }
}

impl Abbreviation for ElectionDataObjectId {
    /// Returns an excessively short string hinting at the value useful only for logging.
    fn abbreviation(&self) -> Cow<'static, str> {
        use ElectionDataObjectId::*;
        match self {
            FixedParameters => "FixedParameters".into(),
            VaryingParameters => "VaryingParameters".into(),
            ElectionParameters => "ElectionParameters".into(),
            BallotStyle => "BallotStyle".into(),
            VotingDeviceInformationSpec => "VotingDeviceInformationSpec".into(),
            ElectionManifest => "ElectionManifest".into(),
            Hashes => "Hashes".into(),
            GuardianKeyPart(GuardianKeyId) => "GuardianKeyPart".into(),
            JointPublicKey(GuardianKeyPurpose) => "JointPublicKey".into(),
            ExtendedBaseHash => "ExtendedBaseHash".into(),
            PreVotingData => "PreVotingData".into(),
            GeneratedTestDataVoterSelections(hv) => format!(
                "GeneratedTestDataVoterSel({})",
                hv.to_string_hex_no_prefix_suffix()
            )
            .into(),
            ElectionTallies => "ElectionTallies".into(),
        }
    }
}

//=================================================================================================|

/// Identifies a data resource, i.e., a type implementing [`Resource`].
///
#[derive(
    Clone,
    Debug,
    derive_more::Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize,
    //valuable::Valuable,
)]
pub enum ResourceId {
    /// The [`ElectionGuardDesignSpecificationVersion`] structure represeting this code implementation,
    /// not necessarily any serialized data.
    ///
    /// This is seemingly trivial (it's already a pub static), but it is useful to have
    /// a successful-by-default case for testing.
    ElectionGuardDesignSpecificationVersion,

    /// The [`Resource_Csrng`], providing a source of random numbers.
    Csrng,

    ElectionDataObject(ElectionDataObjectId),
    // TODO Others? Config?
}

impl ResourceId {
    /// Many [`ResourceId`] variants can recommend a [`ResourcePath`].
    pub fn try_figure_namespace_path(self) -> Option<ResourceNamespacePath> {
        ResourceNamespacePath::try_from_resource_id(self)
    }
}

impl Abbreviation for ResourceId {
    /// Returns an excessively short string hinting at the value useful only for logging.
    fn abbreviation(&self) -> Cow<'static, str> {
        use ResourceId::*;
        match self {
            ElectionGuardDesignSpecificationVersion => "Egdsv".into(),
            Csrng => "Csrng".into(),
            ElectionDataObject(edoid) => edoid.abbreviation(),
        }
    }
}

//=================================================================================================|

/// Specifies the format for Resource production.
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
    serde::Serialize,
    //strum::IntoStaticStr,
    //Valuable,
)]
pub enum ResourceFormat {
    //JsonStr,
    //JsonBytes,
    /// Some type implementing std::io::Read.
    //StdioRead,

    /// A slice of bytes. This implies the object will be read into memory.
    ///
    /// Any resulting Resource object will return Some from [`as_slice_bytes()`](Resource::as_slice_bytes).
    SliceBytes,

    /// An object of the concrete type defined to represent the data.
    ///
    /// Any resulting Resource object will return `Some` from
    /// [`downcast_ref<T>()`](std::any::Any), if `T` is the appropriate type for the
    /// [`ResourceId`].
    ///
    /// Note that this will never be a validated EDO type.
    ConcreteType,

    /// A fully-validated [`ElectionDataObject`].
    ///
    ValidatedElectionDataObject,
}

impl Abbreviation for ResourceFormat {
    /// Returns an excessively short string hinting at the value useful only for logging.
    fn abbreviation(&self) -> Cow<'static, str> {
        use ResourceFormat::*;
        match self {
            SliceBytes => "SliceBytes",
            ConcreteType => "ConcreteType",
            ValidatedElectionDataObject => "ValidatedEdo",
        }
        .into()
    }
}

//static_assertions::assert_impl_all!(ResourceFormat: Valuable);

//=================================================================================================|
/// A simple struct for identifying a data resource by both ID and format.
#[derive(
    Clone,
    //derive_more::Debug,
    //derive_more::Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize,
    //valuable::Valuable,
)]
//#[display("{}ResourceIdFormat {{ rid: {rid}, fmt: {fmt} }}")]
//#[debug("debug:{}{}", __derive_more_f.alternate(), self.abbreviation())]
pub struct ResourceIdFormat {
    pub rid: ResourceId,
    pub fmt: ResourceFormat,
}

impl Abbreviation for ResourceIdFormat {
    /// Returns an excessively short string hinting at the value useful only for logging.
    fn abbreviation(&self) -> Cow<'static, str> {
        format!(
            "({0},{1})",
            self.rid.abbreviation(),
            self.fmt.abbreviation()
        )
        .into()
    }
}

impl std::fmt::Debug for ResourceIdFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "({},{})",
            self.rid.abbreviation(),
            self.fmt.abbreviation()
        )
    }
}

impl std::fmt::Display for ResourceIdFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Debug>::fmt(self, f)
    }
}

//=================================================================================================|
