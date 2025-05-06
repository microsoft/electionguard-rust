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
    string::ToString,
};

use itertools::Itertools;
use serde_tokenstream::from_tokenstream;
use serde_with::{DisplayFromStr, serde_as};
use serde_with::{EnumMap, Map, SerializeDisplay};

use crate::{
    eg::Eg,
    errors::{EgError, EgResult},
    hash::{HValue, HValueByteArray, SpecificHValue, eg_h},
    ident::Ident,
    resource::{ProduceResource, ProduceResourceExt},
    serializable::SerializableCanonical,
};

//? TODO Validatable

//=================================================================================================|

pub trait VdiSpecItemTrait: Clone + std::fmt::Debug + std::fmt::Display {
    fn make_VdiSpecItem(&self) -> VdiSpecItem;
}

//-------------------------------------------------------------------------------------------------|

/// Items that the [`ElectionManifest`] may specify for inclusion in `S_device` string (and the
/// resulting [`VotingDeviceInformationHash`] `H_DI`) that *may contain* voting device information.
#[serde_as]
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
    serde::Serialize
)]
pub enum VdiSpecItem {
    /// Item for the "voting device unique identifier"
    VotingDeviceUniqueIdentifier,

    /// Item for the "possibly other encoded voting device information"
    ///
    /// The [`String`] value should be a valid identifier.
    ///
    /// //? TODO provide some way to validate that a given S_device string actually contains this information.
    #[display("OtherVotingDeviceInfo: {_0}")]
    OtherVotingDeviceInfo(Ident),

    /// Items other than voting device information are supported.
    #[display("NotVotingDeviceInfoItem: {_0}")]
    NotVotingDeviceInfo(NotVotingDeviceInfoItem),
}

impl VdiSpecItem {
    /// Create an [`OtherVotingDeviceInfo`](VdiSpecItem::OtherVotingDeviceInfo) spec item.
    #[inline]
    fn other_voting_device_info<T>(s: T) -> EgResult<Self>
    where
        T: TryInto<Ident>,
        EgError: From<<T as TryInto<Ident>>::Error>,
    {
        let ident: Ident = s.try_into()?;
        let vdi_spec = VdiSpecItem::OtherVotingDeviceInfo(ident);
        Ok(vdi_spec)
    }
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

/*
impl serde::Serialize for VdiSpecItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::{
            Error,
            Serializer, //? SerializeMap, etc.
        };

        match *self {
            VdiSpecItem::VotingDeviceUniqueIdentifier => {
                Serializer::serialize_unit_variant(
                    serializer,
                    "VdiSpecItem",
                    0u32,
                    "VotingDeviceUniqueIdentifier",
                )
            }
            VdiSpecItem::OtherVotingDeviceInfo(ref s) => {
                Serializer::serialize_newtype_variant(
                    serializer,
                    "VdiSpecItem",
                    1u32,
                    "OtherVotingDeviceInfo",
                    s,
                )
            }
            VdiSpecItem::ExplicitlyNotVotingDeviceInformation(ref envdi) => {
                envdi.serialize(serializer)
            }
        }
    }
}
// */

impl SerializableCanonical for VdiSpecItem {}

//=================================================================================================|

/// Items that the [`ElectionManifest`] may specify for inclusion in `S_device` string (and the
/// resulting [`VotingDeviceInformationHash`] `H_DI`) that explicitly *do NOT* contain voting device
/// information.
#[allow(non_camel_case_types)]
#[derive(
    Clone,
    Debug,
    strum_macros::Display,
    strum_macros::EnumString,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde_with::SerializeDisplay,
    serde_with::DeserializeFromStr
)]
pub enum NotVotingDeviceInfoItem {
    /// "voting location unique identifier"
    VotingLocationUniqueIdentifier,
}

impl VdiSpecItemTrait for NotVotingDeviceInfoItem {
    fn make_VdiSpecItem(&self) -> VdiSpecItem {
        VdiSpecItem::NotVotingDeviceInfo(self.clone())
    }
}

impl SerializableCanonical for NotVotingDeviceInfoItem {}

//=================================================================================================|

/// The [`ElectionManifest`] may specify for inclusion in `S_device` string (and the
/// resulting [`VotingDeviceInformationHash`] `H_DI`) an item, qualified as `Required` or `Optional`.
#[allow(non_camel_case_types)]
#[derive(
    Clone,
    Copy,
    Debug,
    strum_macros::Display,
    strum_macros::EnumString,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    //serde::Deserialize,
    //serde::Serialize,
    serde_with::SerializeDisplay,
    serde_with::DeserializeFromStr,
)]
pub enum VdiSpecItem_Requiredness {
    /// The [`VdiSpecItem`] is required.
    Required,

    /// The [`VdiSpecItem`] is optional.
    Optional,
}

impl SerializableCanonical for VdiSpecItem_Requiredness {}

//=================================================================================================|

/// Helper to format a comma-separated list of spec items.
fn vdi_items_set_to_string<T: VdiSpecItemTrait>(items: &BTreeSet<T>) -> String {
    format!("{}", items.iter().format(", "))
}

/*
/// Helper to format a comma-separated list of spec items.
fn map_vdi_items_to_string<T: VdiSpecItemTrait> (
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

#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize
)]
struct NotVotingDeviceInformationRequirednesses(
    #[serde_as(as = "Map<DisplayFromStr, _>")]
    BTreeMap<VdiSpecItem_ExplicitlyNotVotingDeviceInformation, VdiSpecItem_Requiredness>
);
impl NotVotingDeviceInformationRequirednesses {
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize
)]
struct PossibleVotingDeviceInformationRequirednessesMap(
    //#[serde_as(as = "Map<DisplayFromStr, _>")]
    #[serde_as(as = "EnumMap")]
    BTreeMap<VdiSpecItem_ExplicitlyNotVotingDeviceInformation, VdiSpecItem_Requiredness>
);
impl PossibleVotingDeviceInformationRequirednessesMap {
}
// */

//=================================================================================================|

/// Data items the [`ElectionManifest`](eg::election_manifest::ElectionManifest) can specify for
/// inclusion in the `S_device` string (and the resulting [`VotingDeviceInformationHash`] `H_DI`).
///
/// EGDS 2.1.0 Sec 3.4.3 'Voting Device Information' says, "The manifest may specify that `S_device`
/// does not contain voting device information," so this `VotingDeviceInformationSpec` enum reflects
/// that explicit choice at the top-level.
#[serde_as]
#[derive(
    Clone,
    Debug,
    //strum_macros::Display,
    PartialEq,
    Eq,
    //PartialOrd,
    //Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize
)]
pub enum VotingDeviceInformationSpec {
    /// `S_device` contains only items that explicitly do not contain voting device information.
    ///
    /// Mapped value indicates whether the item is required or optional.
    DoesNotContainVotingDeviceInformation(serde_json::Value),

    /// `S_device` allows items that may contain voting device information (in addition to
    /// those that do not).
    ///
    /// Maped value indicates the item is required or optional.
    MayContainVotingDeviceInformation(serde_json::Value),
    //#[strum(to_string = "MayContainVotingDeviceInformation({0})")]
    //PossibleVotingDeviceInformationRequirednessesMap
    //#[display("MayContainVotingDeviceInformation({})", _0)] // map_vdi_items_to_string(_0)
    //MayContainVotingDeviceInformation(
    //    #[serde_as(as = "EnumMap")]
    //    BTreeMap<VdiSpecItem, VdiSpecItem_Requiredness>
    //),
}

impl TryInto<serde_json::Value> for VotingDeviceInformationSpec {
    type Error = EgError;

    /// Attempts to convert a [`VotingDeviceInformationSpec`] into a [`serde_json::Value`].
    #[inline]
    fn try_into(self) -> std::result::Result<serde_json::Value, Self::Error> {
        let json_value = serde_json::to_value(&self)?;
        Ok(json_value)
    }
}

impl VotingDeviceInformationSpec {
    pub fn does_not_contain_voting_device_information(
        map_vdi_items: BTreeMap<NotVotingDeviceInfoItem, VdiSpecItem_Requiredness>,
    ) -> EgResult<Self> {
        let map2: BTreeMap<String, VdiSpecItem_Requiredness> = map_vdi_items
            .iter()
            .map(|(vdi_spec_item, &requiredness)| (vdi_spec_item.to_string(), requiredness))
            .collect();
        let json_value = serde_json::to_value(map2)?;
        let vdi_spec =
            VotingDeviceInformationSpec::DoesNotContainVotingDeviceInformation(json_value);
        Ok(vdi_spec)
    }

    pub fn may_contain_voting_device_information(
        map_vdi_items: BTreeMap<VdiSpecItem, VdiSpecItem_Requiredness>,
    ) -> EgResult<Self> {
        let map2: BTreeMap<String, VdiSpecItem_Requiredness> = map_vdi_items
            .iter()
            .map(|(vdi_spec_item, &requiredness)| (vdi_spec_item.to_string(), requiredness))
            .collect();
        let json_value = serde_json::to_value(map2)?;
        let vdi_spec = VotingDeviceInformationSpec::MayContainVotingDeviceInformation(json_value);
        Ok(vdi_spec)
    }

    /// Validates a specific [`VotingDeviceInformation`] against the [`VotingDeviceInformationSpec`].
    pub fn validate_voting_device_information_against_spec(
        &self,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
        vdi: &VotingDeviceInformation,
    ) -> Result<(), VotingDeviceInformationValidationError> {
        todo!(); //? TODO
    }
}

impl Default for VotingDeviceInformationSpec {
    fn default() -> Self {
        let specitem_device_unique_id =
            VdiSpecItem::VotingDeviceUniqueIdentifier.make_VdiSpecItem();
        let specitem_location_unique_id =
            NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier.make_VdiSpecItem();
        let requiredness_optional = VdiSpecItem_Requiredness::Optional;

        let map_vdi_items: BTreeMap<VdiSpecItem, VdiSpecItem_Requiredness> = [
            (specitem_device_unique_id, requiredness_optional),
            (specitem_location_unique_id, requiredness_optional),
        ]
        .into_iter()
        .collect();

        // Unwrap() is justified here because this is tested and works only with constant data.
        #[allow(clippy::unwrap_used)]
        VotingDeviceInformationSpec::may_contain_voting_device_information(map_vdi_items).unwrap()
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
        vdi_items_set_to_string(disallowed)
    )]
    ItemsNotAllowed { disallowed: BTreeSet<VdiSpecItem> },

    #[error(
        "The voting device information is missing the following item(s) which are required by the election manifest: `{}`",
        vdi_items_set_to_string(missing)
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
    serde::Deserialize,
    serde::Serialize
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
    use anyhow::Context;
    use insta::{assert_json_snapshot, assert_ron_snapshot, assert_snapshot};
    use util::hex_dump::HexDump;

    use super::*;
    use crate::serializable::{SerializableCanonical, SerializablePretty};

    fn print_str(s: &str) {
        eprintln!("vvvvvvvvvvvvvvvvvvvvvv");
        let buf = std::io::Cursor::new(s);
        use std::io::BufRead;
        for (ix, line_result) in buf.lines().enumerate() {
            let line = line_result.unwrap();
            eprintln!("line {:5}: {line}", ix + 1);
        }
        eprintln!("^^^^^^^^^^^^^^^^^^^^^^");
    }

    #[allow(clippy::panic)]
    fn test_json_roundtrip<T>(value: &T)
    where
        T: std::fmt::Debug + serde::Serialize + PartialEq + Eq + Sized,
        T: for<'a> serde::Deserialize<'a>,
    {
        println!("value: {value:#?}");

        let json = serde_json::to_string_pretty(&value).unwrap();

        let value2 = serde_json::from_str::<T>(&json)
            .inspect_err(|e| {
                println!("Error: {e:#?}");
                print_str(&json);
            })
            .unwrap();

        if &value2 != value {
            print_str(&json);
        }

        assert_eq!(&value2, value);
    }

    #[test_log::test]
    fn t1_VdiSpecItem_1_VotingDeviceUniqueIdentifier() {
        let vdi_spec_item = VdiSpecItem::VotingDeviceUniqueIdentifier;
        assert_json_snapshot!(vdi_spec_item, @r#""VotingDeviceUniqueIdentifier""#);
        test_json_roundtrip(&vdi_spec_item);
    }

    #[test_log::test]
    fn t1_VdiSpecItem_2_OtherVotingDeviceInfo_device_color() {
        let ident = "device_color".try_into().unwrap();
        let vdi_spec_item = VdiSpecItem::OtherVotingDeviceInfo(ident);
        assert_json_snapshot!(vdi_spec_item, @r#"
        {
          "OtherVotingDeviceInfo": "device_color"
        }
        "#);
        //? TODO test_json_roundtrip(&vdi_spec_item);
    }

    #[test_log::test]
    fn t1_VdiSpecItem_3_ExplicitlyNotVotingDeviceInformation_VotingLocationUniqueIdentifier() {
        let vdi_spec_item = VdiSpecItem::NotVotingDeviceInfo(
            NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
        );
        assert_json_snapshot!(vdi_spec_item, @r#"
        {
          "NotVotingDeviceInfo": "VotingLocationUniqueIdentifier"
        }
        "#);
        test_json_roundtrip(&vdi_spec_item);
    }

    #[test_log::test]
    fn t2_VotingDeviceInformationSpec_default() {
        let vdi_spec =
            VotingDeviceInformationSpec::DoesNotContainVotingDeviceInformation(Default::default());

        assert_json_snapshot!(vdi_spec, @r#"
        {
          "DoesNotContainVotingDeviceInformation": null
        }
        "#);
        test_json_roundtrip(&vdi_spec);
    }

    #[test_log::test]
    fn t2_Vec_VdiSpecItem() {
        let v_vdi_spec_items: Vec<VdiSpecItem> = [
            VdiSpecItem::VotingDeviceUniqueIdentifier.make_VdiSpecItem(),
            VdiSpecItem::OtherVotingDeviceInfo("mass".try_into().unwrap()).make_VdiSpecItem(),
            NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier.make_VdiSpecItem(),
        ]
        .into_iter()
        .collect();

        assert_json_snapshot!(v_vdi_spec_items, @r#"
        [
          "VotingDeviceUniqueIdentifier",
          {
            "OtherVotingDeviceInfo": "mass"
          },
          {
            "NotVotingDeviceInfo": "VotingLocationUniqueIdentifier"
          }
        ]
        "#);
        test_json_roundtrip(&v_vdi_spec_items);
    }

    /*
    #[test_log::test]
    fn t2_Vec_VdiSpecItem_dyn() {
        let v_vdi_spec_items: Vec<Box<dyn VdiSpecItemTrait + 'static>> = [
            VdiSpecItem_ExplicitlyNotVotingDeviceInformation::VotingLocationUniqueIdentifier,
            VdiSpecItem::OtherVotingDeviceInfo("device_color".to_string()),
        ]
        .into_iter()
        .collect();

        assert_json_snapshot!(v_vdi_spec_items, @r#"
        {
          "DoesNotContainVotingDeviceInformation": {}
        }
        "#);
        test_json_roundtrip(&v_vdi_spec_items);
    }
    // */

    #[test_log::test]
    fn t3() {
        //use VdiSpecItem::*;
        //use NotVotingDeviceInfoItem::*;
        use VdiSpecItem_Requiredness::*;

        /*
        {
            let v: Vec<VdiSpecItem_ExplicitlyNotVotingDeviceInformation> = [
                NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
            ]
            .into_iter()
            .collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&v).unwrap(),
                @r#""[\n  \"VotingLocationUniqueIdentifier\",\n  \"VotingLocationUniqueIdentifier\"\n]""#);
        }
        // */

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
                (
                    NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                    Optional,
                ),
                (
                    NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                    Required,
                ),
            ]
            .into_iter()
            .collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&v).unwrap(),
                @r#""[\n  [\n    \"VotingLocationUniqueIdentifier\",\n    \"Optional\"\n  ],\n  [\n    \"VotingLocationUniqueIdentifier\",\n    \"Required\"\n  ]\n]""#);
        }

        {
            let s: BTreeSet<_> = [
                NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
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

    #[test_log::test]
    fn t4() {
        //use VdiSpecItem::*;
        //use NotVotingDeviceInfoItem::*;
        use VdiSpecItem_Requiredness::*;

        {
            let m: BTreeMap<_, _> = [
                (
                    NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                    Optional,
                ),
                (
                    NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                    Required,
                ),
                (
                    NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                    Required,
                ),
            ]
            .into_iter()
            .collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&m).unwrap(),
                @r#""{\n  \"VotingLocationUniqueIdentifier\": \"Required\"\n}""#);
        }

        {
            let m: BTreeMap<_, _> = [
                (
                    NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                    Optional,
                ),
                (
                    NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                    Required,
                ),
                (
                    NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                    Required,
                ),
            ]
            .into_iter()
            .collect();

            assert_ron_snapshot!(
                serde_json::to_string_pretty(&m).unwrap(),
                @r#""{\n  \"VotingLocationUniqueIdentifier\": \"Required\"\n}""#);
        }
    }

    #[test_log::test]
    fn t5_vdi() {
        let voting_location_unique_id = NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier;
        let requiredness_required = VdiSpecItem_Requiredness::Required;

        let map_vdi_items: BTreeMap<NotVotingDeviceInfoItem, VdiSpecItem_Requiredness> =
            [(voting_location_unique_id, requiredness_required)]
                .into_iter()
                .collect();

        let vdi_spec =
            VotingDeviceInformationSpec::does_not_contain_voting_device_information(map_vdi_items)
                .unwrap();

        assert_ron_snapshot!(
            vdi_spec.to_json_pretty(),
            @r#""{\n  \"DoesNotContainVotingDeviceInformation\": {\n    \"VotingLocationUniqueIdentifier\": \"Required\"\n  }\n}\n\n""#);
    }

    /// Empty [`VotingDeviceInformationSpec::MayContainVotingDeviceInformation`]
    #[test_log::test]
    fn t6() {
        let map_vdi_items: BTreeMap<VdiSpecItem, VdiSpecItem_Requiredness> = [
            // empty
        ]
        .into_iter()
        .collect();

        let vdi_spec =
            VotingDeviceInformationSpec::may_contain_voting_device_information(map_vdi_items)
                .unwrap();

        assert_json_snapshot!(
            vdi_spec.to_json_pretty(),
            @r#""{\n  \"MayContainVotingDeviceInformation\": {}\n}\n\n""#);
    }

    /// A [`VotingDeviceInformationSpec::MayContainVotingDeviceInformation`] with one VdiSpecItem
    #[test_log::test]
    fn t7() {
        //use VdiSpecItem::*;
        //use NotVotingDeviceInfoItem::*;
        use VdiSpecItem_Requiredness::*;

        let vdi_spec_item_other_voting_device_info =
            VdiSpecItem::other_voting_device_info("device_color").unwrap();

        assert_json_snapshot!(vdi_spec_item_other_voting_device_info, @r#"
        {
          "OtherVotingDeviceInfo": "device_color"
        }
        "#);
    }

    /// A [`VotingDeviceInformationSpec::MayContainVotingDeviceInformation`] with one VdiSpecItem
    #[test_log::test]
    fn t8() {
        //use VdiSpecItem::*;
        //use NotVotingDeviceInfoItem::*;
        use VdiSpecItem_Requiredness::*;

        assert_json_snapshot!(VdiSpecItem::VotingDeviceUniqueIdentifier.to_json_pretty(), @r#""\"VotingDeviceUniqueIdentifier\"\n\n""#);

        let vdi_spec_item_other_voting_device_info =
            VdiSpecItem::other_voting_device_info("device_color").unwrap();
        assert_json_snapshot!(vdi_spec_item_other_voting_device_info.to_json_pretty(), @r#""{\n  \"OtherVotingDeviceInfo\": \"device_color\"\n}\n\n""#);

        let voting_location_unique_identifier =
            NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier;
        assert_json_snapshot!(voting_location_unique_identifier.make_VdiSpecItem().to_json_pretty(), @r#""{\n  \"NotVotingDeviceInfo\": \"VotingLocationUniqueIdentifier\"\n}\n\n""#);
        assert_json_snapshot!(VdiSpecItem::NotVotingDeviceInfo(voting_location_unique_identifier).to_json_pretty(), @r#""{\n  \"NotVotingDeviceInfo\": \"VotingLocationUniqueIdentifier\"\n}\n\n""#);

        let specitem_device_unique_id =
            VdiSpecItem::VotingDeviceUniqueIdentifier.make_VdiSpecItem();
        let specitem_device_color =
            VdiSpecItem::OtherVotingDeviceInfo("device_color".try_into().unwrap())
                .make_VdiSpecItem();
        let specitem_location_unique_id =
            NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier.make_VdiSpecItem();

        let requiredness_optional = VdiSpecItem_Requiredness::Optional;
        let requiredness_required = VdiSpecItem_Requiredness::Required;

        let map_vdi_items: BTreeMap<VdiSpecItem, VdiSpecItem_Requiredness> = [
            (specitem_device_unique_id, requiredness_optional),
            (specitem_device_color, requiredness_required),
            (specitem_location_unique_id, requiredness_required),
        ]
        .into_iter()
        .collect();

        let vdi_spec =
            VotingDeviceInformationSpec::may_contain_voting_device_information(map_vdi_items)
                .unwrap();

        assert_json_snapshot!(
            vdi_spec,
            @r#"
        {
          "MayContainVotingDeviceInformation": {
            "NotVotingDeviceInfoItem: VotingLocationUniqueIdentifier": "Required",
            "OtherVotingDeviceInfo: device_color": "Required",
            "VotingDeviceUniqueIdentifier": "Optional"
          }
        }
        "#);
    }

    #[test_log::test]
    fn t9() {
        //use VdiSpecItem::*;
        //use NotVotingDeviceInfoItem::*;
        use VdiSpecItem_Requiredness::*;

        let vdi_spec_default = VotingDeviceInformationSpec::default();

        assert_json_snapshot!(vdi_spec_default,
        @r#"
        {
          "MayContainVotingDeviceInformation": {
            "NotVotingDeviceInfoItem: VotingLocationUniqueIdentifier": "Optional",
            "VotingDeviceUniqueIdentifier": "Optional"
          }
        }
        "#);

        /*
        assert_ron_snapshot!(
            vdi_spec_default,
            @r#"
        MayContainVotingDeviceInformation({
          "VotingDeviceUniqueIdentifier": Optional,
          "VotingLocationUniqueIdentifier": Optional,
        })
        "#);

        assert_ron_snapshot!(
            serde_json::to_string_pretty(&vdi_spec_default).unwrap(),
            @r#""{
              \"MayContainVotingDeviceInformation\": {
                \"VotingDeviceUniqueIdentifier\": \"Optional\",
                \"VotingLocationUniqueIdentifier\": \"Optional\"
              }
            }""#);

        assert_ron_snapshot!(
            vdi_spec_default.to_json_pretty(),
            @r#""{
              \"MayContainVotingDeviceInformation\": {
                \"VotingDeviceUniqueIdentifier\": \"Optional\",
                \"VotingLocationUniqueIdentifier\": \"Optional\"
              }
            }

            ""#);
        // */
    }

    #[ignore] //? TODO
    #[test_log::test]
    fn t10() {
        //use VdiSpecItem::*;
        //use NotVotingDeviceInfo::*;
        use VdiSpecItem_Requiredness::*;

        let map_vdi_items: BTreeMap<VdiSpecItem, VdiSpecItem_Requiredness> = [
            (VdiSpecItem::VotingDeviceUniqueIdentifier, Required),
            (
                VdiSpecItem::OtherVotingDeviceInfo("device_color".try_into().unwrap()),
                Optional,
            ),
            (
                VdiSpecItem::NotVotingDeviceInfo(
                    NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                ),
                Required,
            ),
        ]
        .into_iter()
        .collect();

        let json_value = serde_json::to_value(map_vdi_items).unwrap();

        let vdi_spec = VotingDeviceInformationSpec::MayContainVotingDeviceInformation(json_value);

        assert_ron_snapshot!(
            vdi_spec,
            @r#"
        MayContainVotingDeviceInformation({
          VotingDeviceUniqueIdentifier: Required,
          OtherVotingDeviceInfo("device_color"): Optional,
          VotingLocationUniqueIdentifier: Required,
        })
        "#);

        #[rustfmt::skip]
        assert_snapshot!(vdi_spec.to_json_pretty(), @r#"
        {
          "MayContainVotingDeviceInformation": {
            "VotingDeviceUniqueIdentifier": "Required",
        "#);
    }

    fn make_vdi() -> VotingDeviceInformation {
        VotingDeviceInformation(
            [
                (VdiSpecItem::VotingDeviceUniqueIdentifier, "SN:00001234"),
                (
                    VdiSpecItem::OtherVotingDeviceInfo("device_color".try_into().unwrap()),
                    "beige",
                ),
                (
                    VdiSpecItem::NotVotingDeviceInfo(
                        NotVotingDeviceInfoItem::VotingLocationUniqueIdentifier,
                    ),
                    "Null Island",
                ),
            ]
            .into_iter()
            .map(|pr| (pr.0, pr.1.to_string()))
            .collect(),
        )
    }

    #[test_log::test]
    fn t11() {
        // Test an example VotingDeviceInformation.
        let vdi = make_vdi();

        assert_ron_snapshot!(
            vdi,
            @r#"
        VotingDeviceInformation({
          VotingDeviceUniqueIdentifier: "SN:00001234",
          OtherVotingDeviceInfo(Ident("device_color")): "beige",
          NotVotingDeviceInfo("VotingLocationUniqueIdentifier"): "Null Island",
        })
        "#);
    }

    #[test_log::test]
    fn t12() {
        // Test an example VotingDeviceInformation.
        let vdi = make_vdi();

        let s_device = vdi.s_device_str().unwrap();
        assert_ron_snapshot!(
            s_device,
            @r#""{\"VotingDeviceUniqueIdentifier\":\"SN:00001234\",""#);

        let v = Vec::<u8>::new();
        let v = vdi.extend_with_encoded_s_device(v).unwrap();

        assert_ron_snapshot!(
            HexDump::new().dump(&v).to_string(),
            @r#""0000  00 00 00 2e 7b 22 56 6f 74 69 6e 67 44 65 76 69  ....{\"VotingDevi\n0010  63 65 55 6e 69 71 75 65 49 64 65 6e 74 69 66 69  ceUniqueIdentifi\n0020  65 72 22 3a 22 53 4e 3a 30 30 30 30 31 32 33 34  er\":\"SN:00001234\n0030  22 2c                                            \",""#);
    }

    /*
    #[test_log::test]
    fn t13() -> EgResult<()> {
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
