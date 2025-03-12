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

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    eg::Eg,
    errors::{EgError, EgResult},
    hash::{HValue, HValueByteArray, SpecificHValue, eg_h},
    resource::{ProduceResource, ProduceResourceExt},
    serializable::SerializableCanonical,
};

//? TODO Validatable

//=================================================================================================|

pub trait VdiSpecItemTrait: Clone + std::fmt::Debug + std::fmt::Display {
    fn make_VdiSpecItem(&self) -> VdiSpecItem;
}

/// Items that the [`ElectionManifest`] may specify for inclusion in `S_device` string (and the
/// resulting [`VotingDeviceInformationHash`] `H_DI`) that *may contain* voting device information.
#[derive(
    Clone,
    Debug,
    derive_more::Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize
)]
#[serde(into = "String")]
pub enum VdiSpecItem {
    /// "voting device unique identifier"
    VotingDeviceUniqueIdentifier,

    /// "possibly other encoded voting device information"
    ///
    /// The [`String`] value should be a valid identifier.
    ///
    /// //? TODO provide some way to validate that a given S_device string actually contains this information.
    #[display("OtherVotingDeviceInformation: {_0}")]
    OtherVotingDeviceInformation(String),

    /// Items other than voting device information are supported.
    ExplicitlyNotVotingDeviceInformation(VdiSpecItem_ExplicitlyNotVotingDeviceInformation),
}

impl From<VdiSpecItem> for String {
    fn from(src: VdiSpecItem) -> Self {
        src.to_string()
    }
}

impl VdiSpecItemTrait for VdiSpecItem {
    fn make_VdiSpecItem(&self) -> VdiSpecItem {
        self.clone()
    }
}

impl SerializableCanonical for VdiSpecItem {}

//=================================================================================================|

/// Items that the [`ElectionManifest`] may specify for inclusion in `S_device` string (and the
/// resulting [`VotingDeviceInformationHash`] `H_DI`) that explicitly *do NOT* contain voting device
/// information.
#[allow(non_camel_case_types)]
#[derive(
    Clone,
    Debug,
    derive_more::Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize
)]
pub enum VdiSpecItem_ExplicitlyNotVotingDeviceInformation {
    /// "unique voting location identifier"
    VotingLocationUniqueIdentifier,
}

impl VdiSpecItemTrait for VdiSpecItem_ExplicitlyNotVotingDeviceInformation {
    fn make_VdiSpecItem(&self) -> VdiSpecItem {
        VdiSpecItem::ExplicitlyNotVotingDeviceInformation(self.clone())
    }
}

impl SerializableCanonical for VdiSpecItem_ExplicitlyNotVotingDeviceInformation {}

//=================================================================================================|

/// The [`ElectionManifest`] may specify for inclusion in `S_device` string (and the
/// resulting [`VotingDeviceInformationHash`] `H_DI`) an item, qualified as `Required` or `Optional`.
#[allow(non_camel_case_types)]
#[derive(
    Clone,
    Debug,
    derive_more::Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize
)]
pub enum VdiSpecItem_Requiredness {
    /// The [`VdiSpecItem`] is required.
    Required,

    /// The [`VdiSpecItem`] is optional.
    Optional,
}

impl SerializableCanonical for VdiSpecItem_Requiredness {}

//=================================================================================================|

/// Data items the [`ElectionManifest`](eg::election_manifest::ElectionManifest) can specify for
/// inclusion in the `S_device` string (and the resulting [`VotingDeviceInformationHash`] `H_DI`).
///
/// EGDS 2.1.0 Sec 3.4.3 'Voting Device Information' says, "The manifest may specify that `S_device`
/// does not contain voting device information," so this `VotingDeviceInformationSpec` enum reflects
/// that explicit choice at the top-level.
#[derive(
    Clone,
    Debug,
    derive_more::Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize
)]
pub enum VotingDeviceInformationSpec {
    /// `S_device` contains only items that explicitly do not contain voting device information.
    ///
    /// Mapped value indicates whether the item is required or optional.
    #[display(
        "DoesNotContainVotingDeviceInformation({})",
        Self::map_vdi_items_to_string(_0)
    )]
    DoesNotContainVotingDeviceInformation(
        BTreeMap<VdiSpecItem_ExplicitlyNotVotingDeviceInformation, VdiSpecItem_Requiredness>,
    ),

    /// `S_device` allows items that may contain voting device information (in addition to
    /// those that do not).
    ///
    /// Maped value indicates the item is required or optional.
    #[display(
        "MayContainVotingDeviceInformation({})",
        Self::map_vdi_items_to_string(_0)
    )]
    MayContainVotingDeviceInformation(BTreeMap<VdiSpecItem, VdiSpecItem_Requiredness>),
}

impl VotingDeviceInformationSpec {
    /// Validates a specific [`VotingDeviceInformation`] against the [`VotingDeviceInformationSpec`].
    pub fn validate_voting_device_information_against_spec(
        &self,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        vdi: &VotingDeviceInformation,
    ) -> Result<(), VotingDeviceInformationValidationError> {
        todo!(); //? TODO
    }

    /// Helper to format a comma-separated list of spec items.
    pub(crate) fn vdi_items_set_to_string<T: VdiSpecItemTrait>(items: &BTreeSet<T>) -> String {
        format!("{}", items.iter().format(", "))
    }

    /// Helper to format a comma-separated list of spec items.
    pub(crate) fn map_vdi_items_to_string<T: VdiSpecItemTrait>(
        items: &BTreeMap<T, VdiSpecItem_Requiredness>,
    ) -> String {
        format!(
            "{}",
            items.iter().format_with(", ", |pr, f| {
                f(pr.0)
                    .and_then(|_| f(&" ("))
                    .and_then(|_| f(pr.1))
                    .and_then(|_| f(&")"))
            })
        )
    }
}

impl Default for VotingDeviceInformationSpec {
    fn default() -> Self {
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;
        use VotingDeviceInformationSpec::*;

        let map_vdi_items: BTreeMap<VdiSpecItem, VdiSpecItem_Requiredness> =
            [(VotingLocationUniqueIdentifier.make_VdiSpecItem(), Optional)]
                .into_iter()
                .collect();
        VotingDeviceInformationSpec::MayContainVotingDeviceInformation(map_vdi_items)
    }
}

crate::impl_knows_friendly_type_name! { VotingDeviceInformationSpec }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { VotingDeviceInformationSpec, VotingDeviceInformationSpec }

impl SerializableCanonical for VotingDeviceInformationSpec {}

//=================================================================================================|

/// [`Result::Err`](std::result::Result) type resulting from validating a
/// [`VotingDeviceInformation`] against a [`VotingDeviceInformationSpec`].
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[allow(non_camel_case_types)]
pub enum VotingDeviceInformationValidationError {
    #[error(
        "The voting device information contains the following item(s) which are not allowed by the election manifest: `{}`.",
        VotingDeviceInformationSpec::vdi_items_set_to_string(disallowed)
    )]
    ItemsNotAllowed { disallowed: BTreeSet<VdiSpecItem> },

    #[error(
        "The voting device information is missing the following item(s) which are required by the election manifest: `{}`",
        VotingDeviceInformationSpec::vdi_items_set_to_string(missing)
    )]
    ItemsMissing { missing: BTreeSet<VdiSpecItem> },
}

//=================================================================================================|

/// EGDS 2.1.0 Sec 3.4.3 Voting Device Information
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize
)]
pub struct VotingDeviceInformation(BTreeMap<VdiSpecItem, String>);

impl VotingDeviceInformation {
    /// Creates a new, empty [`VotingDeviceInformation`].
    pub fn new_empty() -> Self {
        Self(BTreeMap::default())
    }

    // The string `S_device`. The Rust [`String`](std::string::String) type enforces UTF-8.
    // Does not include the leading 4-byte length.
    pub fn s_device_str(&self) -> EgResult<String> {
        self.to_canonical_bytes()
            .map_err(Into::<EgError>::into)
            .and_then(|vby| String::from_utf8(vby).map_err(Into::<EgError>::into))
    }

    /// Encodes `S_device` as described in EGDS 2.1.0 Sec 3.4.3, to the supplied byte vector.
    ///
    /// - 4-byte length in bytes (big-endian)
    /// - that many bytes of string data in UTF-8
    ///
    /// If there's an error, you *may* get your original buffer back.
    ///
    pub fn extend_with_encoded_s_device(
        &self,
        mut v: Vec<u8>,
    ) -> Result<Vec<u8>, (EgError, Option<Vec<u8>>)> {
        use std::io::Cursor;

        // Save the hash of the original vec
        let hv0 = eg_h(
            HValue::default(),
            b"Checking if we recovered original data in the event of error",
        );

        let h_original_data = eg_h(&hv0, &v);

        let v_len_initial_usize = v.len();

        let pos_initial = match u64::try_from(v_len_initial_usize) {
            Ok(pos) => pos,
            Err(e) => {
                return Err((e.into(), Some(v)));
            }
        };

        fn f(
            self_: &VotingDeviceInformation,
            buf: &mut Cursor<Vec<u8>>,
            pos_initial: u64,
        ) -> EgResult<()> {
            let pos_begin_utf8 =
                pos_initial
                    .checked_add(4)
                    .ok_or_else(|| EgError::UnexpectedValue_u64 {
                        thing_name: "starting position",
                        expected: 0..=(isize::MAX - 4) as u64,
                        actual: pos_initial,
                    })?;

            buf.set_position(pos_begin_utf8);
            self_.to_stdiowrite_canonical(buf)?;

            let pos_end = buf.position();

            let bytes_written = pos_end.checked_sub(pos_begin_utf8).ok_or_else(|| {
                EgError::UnexpectedValue_u64 {
                    thing_name: "end position",
                    expected: 4..=isize::MAX as u64,
                    actual: pos_end,
                }
            })?;

            let expected = 0..=u32::MAX as u64;
            if !expected.contains(&bytes_written) {
                return Err(EgError::UnexpectedValue_u64 {
                    thing_name: "s_device string bytes written",
                    expected,
                    actual: bytes_written,
                });
            };

            let s_len_u32: u32 = bytes_written as u32;

            buf.set_position(pos_initial);
            buf.write_all(&s_len_u32.to_be_bytes())
                .map_err(Into::<EgError>::into)?;

            Ok(())
        }

        let mut buf = Cursor::new(std::mem::take(&mut v));

        let result = f(self, &mut buf, pos_initial);

        let mut v = buf.into_inner();

        if let Err(e) = result {
            // Try to put the original v back the way it was by trimming any data added.
            v.truncate(v_len_initial_usize);

            // See if it worked
            let original_data_matches: bool =
                v.len() == v_len_initial_usize && eg_h(&hv0, &v) == h_original_data;

            return Err((e, original_data_matches.then_some(v)));
        }

        Ok(v)
    }
}

crate::impl_knows_friendly_type_name! { VotingDeviceInformation }

crate::impl_MayBeResource_for_non_Resource! { VotingDeviceInformation } //? TODO maybe not simple: crate::impl_Resource_for_simple_ElectionDataObjectId_type! { VotingDeviceInformationSpec, VotingDeviceInformationSpec }

impl SerializableCanonical for VotingDeviceInformation {}

impl std::fmt::Display for VotingDeviceInformation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let items_list = self.0.iter().format_with("),\n(", |pr, f| {
            f(&"\n    (")
                .and_then(|_| f(pr.0))
                .and_then(|_| f(&": "))
                .and_then(|_| f(pr.1))
        });
        write!(f, "VotingDeviceInformation {{ {items_list})\n}}")
    }
}

//=================================================================================================|

#[allow(non_camel_case_types)]
pub struct VotingDeviceInformationHash_tag;

/// EGDS 2.1.0 Sec 3.4.3 Voting Device Information
///
/// Eq. 72  H_DI = H(H_E; 0x2A, S_device)
///
pub type VotingDeviceInformationHash = SpecificHValue<VotingDeviceInformationHash_tag>;

impl VotingDeviceInformationHash {
    /// EGDS 2.1.0 Sec 3.4.3 Voting Device Information
    ///
    /// Eq. 72  H_DI = H(H_E; 0x2A, S_device)
    ///
    pub async fn compute_from_voting_device_information(
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        vdi: &VotingDeviceInformation,
    ) -> EgResult<Self> {
        let extended_base_hash = produce_resource.extended_base_hash().await?;
        let extended_base_hash = extended_base_hash.as_ref();
        let h_e = extended_base_hash.h_e();

        //let expected_len = 5 + s_device.len(); // EGDS 2.1.0 pg. 76 (72)

        let mut v = vec![0x2A];
        let v = vdi
            .extend_with_encoded_s_device(v)
            .map_err(|(e, _opt_v)| e)?;

        //assert_eq!(v.len(), expected_len);

        let h_di = VotingDeviceInformationHash::compute_from_eg_h(h_e, v);

        Ok(h_di)
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use insta::assert_ron_snapshot;
    use util::hex_dump::HexDump;

    use super::*;
    use crate::serializable::{SerializableCanonical, SerializablePretty};

    #[test]
    fn t0() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;

        assert_ron_snapshot!(
            VotingDeviceUniqueIdentifier,
            @r#""VotingDeviceUniqueIdentifier""#);
        assert_ron_snapshot!(
            OtherVotingDeviceInformation("device_color".to_string()),
            @r#""OtherVotingDeviceInformation: device_color""#);
        assert_ron_snapshot!(ExplicitlyNotVotingDeviceInformation(
            VdiSpecItem_ExplicitlyNotVotingDeviceInformation::VotingLocationUniqueIdentifier),
            @r#""VotingLocationUniqueIdentifier""#);

        assert_ron_snapshot!(
            VotingDeviceUniqueIdentifier.to_json_pretty(),
            @r#""\"VotingDeviceUniqueIdentifier\"\n\n""#);
        assert_ron_snapshot!(
            OtherVotingDeviceInformation("device_color".to_string()).to_json_pretty(),
            @r#""\"OtherVotingDeviceInformation: device_color\"\n\n""#);
        assert_ron_snapshot!(
            ExplicitlyNotVotingDeviceInformation(VotingLocationUniqueIdentifier).to_json_pretty(),
            @r#""\"VotingLocationUniqueIdentifier\"\n\n""#);
    }

    #[test]
    fn t1() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        let vdi_spec_empty =
            VotingDeviceInformationSpec::DoesNotContainVotingDeviceInformation(Default::default());

        assert_ron_snapshot!(
            vdi_spec_empty.to_json_pretty(),
            @r#""{\n  \"DoesNotContainVotingDeviceInformation\": {}\n}\n\n""#);
    }

    #[test]
    fn t2() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        {
            let v: Vec<VdiSpecItem_ExplicitlyNotVotingDeviceInformation> = [
                VotingLocationUniqueIdentifier,
                VotingLocationUniqueIdentifier,
            ]
            .into_iter()
            .collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&v).unwrap(),
                @r#""[\n  \"VotingLocationUniqueIdentifier\",\n  \"VotingLocationUniqueIdentifier\"\n]""#);
        }

        {
            let v: Vec<VdiSpecItem_Requiredness> = [Optional, Required, Required, Optional]
                .into_iter()
                .collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&v).unwrap(),
                @r#""[\n  \"Optional\",\n  \"Required\",\n  \"Required\",\n  \"Optional\"\n]""#);
        }

        {
            let v: Vec<_> = [
                (VotingLocationUniqueIdentifier, Optional),
                (VotingLocationUniqueIdentifier, Required),
            ]
            .into_iter()
            .collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&v).unwrap(),
                @r#""[\n  [\n    \"VotingLocationUniqueIdentifier\",\n    \"Optional\"\n  ],\n  [\n    \"VotingLocationUniqueIdentifier\",\n    \"Required\"\n  ]\n]""#);
        }

        {
            let s: BTreeSet<_> = [
                VotingLocationUniqueIdentifier,
                VotingLocationUniqueIdentifier,
            ]
            .into_iter()
            .collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&s).unwrap(),
                @r#""[\n  \"VotingLocationUniqueIdentifier\"\n]""#);
        }

        {
            let s: BTreeSet<_> = [Optional, Required, Optional].into_iter().collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&s).unwrap(),
                @r#""[\n  \"Required\",\n  \"Optional\"\n]""#);
        }
    }

    #[test]
    fn t3() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        {
            let m: BTreeMap<_, _> = [
                (VotingLocationUniqueIdentifier, Optional),
                (VotingLocationUniqueIdentifier, Required),
                (VotingLocationUniqueIdentifier, Required),
            ]
            .into_iter()
            .collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&m).unwrap(),
                @r#""{\n  \"VotingLocationUniqueIdentifier\": \"Required\"\n}""#);
        }

        {
            let m: BTreeMap<_, _> = [
                (VotingLocationUniqueIdentifier, Optional),
                (VotingLocationUniqueIdentifier, Required),
                (VotingLocationUniqueIdentifier, Required),
            ]
            .into_iter()
            .collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&m).unwrap(),
                @r#""{\n  \"VotingLocationUniqueIdentifier\": \"Required\"\n}""#);
        }
    }

    #[test]
    fn t4() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        let vdi_spec_empty = VotingDeviceInformationSpec::DoesNotContainVotingDeviceInformation(
            [(VotingLocationUniqueIdentifier, Required)]
                .into_iter()
                .collect(),
        );

        assert_ron_snapshot!(
            vdi_spec_empty.to_json_pretty(),
            @r#""{\n  \"DoesNotContainVotingDeviceInformation\": {\n    \"VotingLocationUniqueIdentifier\": \"Required\"\n  }\n}\n\n""#);
    }

    /// Empty [`VotingDeviceInformationSpec::MayContainVotingDeviceInformation`]
    #[test]
    fn t5() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        let vdi_spec_empty = VotingDeviceInformationSpec::MayContainVotingDeviceInformation(
            [].into_iter()
                .collect::<BTreeMap<VdiSpecItem, VdiSpecItem_Requiredness>>(),
        );

        assert_ron_snapshot!(
            vdi_spec_empty.to_json_pretty(),
            @r#""{\n  \"MayContainVotingDeviceInformation\": {}\n}\n\n""#);
    }

    /// A [`VotingDeviceInformationSpec::MayContainVotingDeviceInformation`] with one VdiSpecItem
    #[test]
    fn t6() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        assert_ron_snapshot!(OtherVotingDeviceInformation("color".to_string()).to_string(), @r#""OtherVotingDeviceInformation: color""#);
    }

    /// A [`VotingDeviceInformationSpec::MayContainVotingDeviceInformation`] with one VdiSpecItem
    #[test]
    fn t7() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        assert_ron_snapshot!(VotingDeviceUniqueIdentifier.to_json_pretty(), @r#""\"VotingDeviceUniqueIdentifier\"\n\n""#);
        assert_ron_snapshot!(OtherVotingDeviceInformation("color".to_string()).to_json_pretty(), @r#""\"OtherVotingDeviceInformation: color\"\n\n""#);
        assert_ron_snapshot!(VotingLocationUniqueIdentifier.make_VdiSpecItem().to_json_pretty(), @r#""\"VotingLocationUniqueIdentifier\"\n\n""#);
        assert_ron_snapshot!(ExplicitlyNotVotingDeviceInformation(VotingLocationUniqueIdentifier).to_json_pretty(), @r#""\"VotingLocationUniqueIdentifier\"\n\n""#);

        let vdi_spec_with_VotingDeviceUniqueIdentifier =
            VotingDeviceInformationSpec::MayContainVotingDeviceInformation(
                [
                    //(VotingDeviceUniqueIdentifier, Optional), // works
                    (OtherVotingDeviceInformation("color".to_string()), Required), // Error("key must be a string"
                    (VotingLocationUniqueIdentifier.make_VdiSpecItem(), Required), // Error("key must be a string"
                    (
                        ExplicitlyNotVotingDeviceInformation(VotingLocationUniqueIdentifier),
                        Required,
                    ), // Error("key must be a string"
                ]
                .into_iter()
                .collect::<BTreeMap<VdiSpecItem, VdiSpecItem_Requiredness>>(),
            );

        assert_ron_snapshot!(
            vdi_spec_with_VotingDeviceUniqueIdentifier.to_json_pretty(),
            @r#""{\n  \"MayContainVotingDeviceInformation\": {\n    \"OtherVotingDeviceInformation: color\": \"Required\",\n    \"VotingLocationUniqueIdentifier\": \"Required\"\n  }\n}\n\n""#);
    }

    #[test]
    fn t8() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        let vdi_spec_default = VotingDeviceInformationSpec::default();

        assert_ron_snapshot!(
            vdi_spec_default,
            @r#"
        MayContainVotingDeviceInformation({
          "VotingLocationUniqueIdentifier": Optional,
        })
        "#);

        assert_ron_snapshot!(
            serde_json::to_string_pretty(&vdi_spec_default).unwrap(),
            @r#""{\n  \"MayContainVotingDeviceInformation\": {\n    \"VotingLocationUniqueIdentifier\": \"Optional\"\n  }\n}""#);

        assert_ron_snapshot!(
            vdi_spec_default.to_json_pretty(),
            @r#""{\n  \"MayContainVotingDeviceInformation\": {\n    \"VotingLocationUniqueIdentifier\": \"Optional\"\n  }\n}\n\n""#);
    }

    #[test]
    fn t9() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        let vdi_spec: VotingDeviceInformationSpec =
            VotingDeviceInformationSpec::MayContainVotingDeviceInformation(
                [
                    (VotingDeviceUniqueIdentifier, Required),
                    (
                        OtherVotingDeviceInformation("device_color".to_string()),
                        Optional,
                    ),
                    (
                        ExplicitlyNotVotingDeviceInformation(VotingLocationUniqueIdentifier),
                        Required,
                    ),
                ]
                .into_iter()
                .collect(),
            );

        assert_ron_snapshot!(
            vdi_spec,
            @r#"
        MayContainVotingDeviceInformation({
          "VotingDeviceUniqueIdentifier": Required,
          "OtherVotingDeviceInformation: device_color": Optional,
          "VotingLocationUniqueIdentifier": Required,
        })
        "#);

        assert_ron_snapshot!(
            vdi_spec.to_json_pretty(),
            @r#""{\n  \"MayContainVotingDeviceInformation\": {\n    \"VotingDeviceUniqueIdentifier\": \"Required\",\n    \"OtherVotingDeviceInformation: device_color\": \"Optional\",\n    \"VotingLocationUniqueIdentifier\": \"Required\"\n  }\n}\n\n""#);
    }

    fn make_vdi() -> VotingDeviceInformation {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        VotingDeviceInformation(
            [
                (VotingDeviceUniqueIdentifier, "SN:00001234"),
                (
                    OtherVotingDeviceInformation("device_color".to_string()),
                    "beige",
                ),
                (
                    ExplicitlyNotVotingDeviceInformation(VotingLocationUniqueIdentifier),
                    "Null Island",
                ),
            ]
            .into_iter()
            .map(|pr| (pr.0, pr.1.to_string()))
            .collect(),
        )
    }

    #[test]
    fn t10() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        // Test an example VotingDeviceInformation.
        let vdi = make_vdi();

        assert_ron_snapshot!(
            vdi,
            @r#"
        VotingDeviceInformation({
          "VotingDeviceUniqueIdentifier": "SN:00001234",
          "OtherVotingDeviceInformation: device_color": "beige",
          "VotingLocationUniqueIdentifier": "Null Island",
        })
        "#);
    }

    #[test]
    fn t11() {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        // Test an example VotingDeviceInformation.
        let vdi = make_vdi();

        let s_device = vdi.s_device_str().unwrap();
        assert_ron_snapshot!(
            s_device,
            @r#""{\"VotingDeviceUniqueIdentifier\":\"SN:00001234\",\"OtherVotingDeviceInformation: device_color\":\"beige\",\"VotingLocationUniqueIdentifier\":\"Null Island\"}""#);

        let v = Vec::<u8>::new();
        let v = vdi.extend_with_encoded_s_device(v).unwrap();

        assert_ron_snapshot!(
            HexDump::new().dump(&v).to_string(),
            @r#""0000  00 00 00 92 7b 22 56 6f 74 69 6e 67 44 65 76 69  ....{\"VotingDevi\n0010  63 65 55 6e 69 71 75 65 49 64 65 6e 74 69 66 69  ceUniqueIdentifi\n0020  65 72 22 3a 22 53 4e 3a 30 30 30 30 31 32 33 34  er\":\"SN:00001234\n0030  22 2c 22 4f 74 68 65 72 56 6f 74 69 6e 67 44 65  \",\"OtherVotingDe\n0040  76 69 63 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 3a  viceInformation:\n0050  20 64 65 76 69 63 65 5f 63 6f 6c 6f 72 22 3a 22  .device_color\":\"\n0060  62 65 69 67 65 22 2c 22 56 6f 74 69 6e 67 4c 6f  beige\",\"VotingLo\n0070  63 61 74 69 6f 6e 55 6e 69 71 75 65 49 64 65 6e  cationUniqueIden\n0080  74 69 66 69 65 72 22 3a 22 4e 75 6c 6c 20 49 73  tifier\":\"Null.Is\n0090  6c 61 6e 64 22 7d                                land\"}""#);
    }

    /*
    #[test]
    fn t12() -> EgResult<()> {
        use VdiSpecItem::*;
        use VdiSpecItem_ExplicitlyNotVotingDeviceInformation::*;
        use VdiSpecItem_Requiredness::*;

        let eg = Eg::new_insecure_deterministic_with_example_election_data(
            "eg::voting_device::test::t11",
        )?;
        let eg = eg.as_ref();

        let arc_extended_base_hash = eg.extended_base_hash().await.unwrap();
        let h_e = arc_extended_base_hash.h_e();

        // Test an example VotingDeviceInformation.
        let vdi = make_vdi();

        let vdih =
            VotingDeviceInformationHash::compute_from_voting_device_information(eg, &vdi)?;
        assert_ron_snapshot!(
            vdih,
            @r#""#);

        assert_ron_snapshot!(
            HexDump::new().dump(vdih.0.0.as_slice()).to_string(),
            @r#""#);

        Ok(())
    }
    // */
}
