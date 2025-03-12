// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    eg::Eg,
    errors::EgError,
    guardian::GuardianIndex,
    resource::{ProduceResource, ProduceResourceExt},
    serializable::SerializableCanonical,
};

/// Ballot chaining.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BallotChaining {
    Prohibited,
    Allowed,
    Required,
}

/// The parameters for a specific election.
#[derive(Debug, Clone, Serialize)]
pub struct VaryingParametersInfo {
    /// Number of guardians.
    pub n: GuardianIndex,

    /// Decryption quorum threshold value.
    pub k: GuardianIndex,

    /// Jurisdictional information string. This can be used to specify a location.
    pub info: String,

    /// Ballot chaining.
    pub ballot_chaining: BallotChaining,

    /// Date. Optional, can be empty.
    /// Consider using [RFC 3339](https://datatracker.ietf.org/doc/rfc3339/) or "ISO 8601" format.
    pub date: String,
}

crate::impl_knows_friendly_type_name! { VaryingParametersInfo }

crate::impl_Resource_for_simple_ElectionDataObjectId_info_type! { VaryingParametersInfo, VaryingParameters }

impl SerializableCanonical for VaryingParametersInfo {}

impl<'de> Deserialize<'de> for VaryingParametersInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use strum::{IntoStaticStr, VariantNames};

        #[derive(Deserialize, IntoStaticStr, VariantNames)]
        #[serde(field_identifier)]
        #[allow(non_camel_case_types)]
        enum Field {
            n,
            k,
            info,
            ballot_chaining,
            date,
        }

        struct VaryingParametersInfoVisitor;

        impl<'de> Visitor<'de> for VaryingParametersInfoVisitor {
            type Value = VaryingParametersInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("VaryingParametersInfo")
            }

            #[allow(dependency_on_unit_never_type_fallback)] //? TODO temp code
            fn visit_map<MapAcc>(
                self,
                mut map: MapAcc,
            ) -> Result<VaryingParametersInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let Some((Field::n, n)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field(Field::n.into()));
                };

                let Some((Field::k, k)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field(Field::k.into()));
                };

                let Some((Field::info, info)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field(Field::info.into()));
                };

                let Some((Field::ballot_chaining, ballot_chaining)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field(Field::ballot_chaining.into()));
                };

                let (opt_date, next_entry): (Option<String>, Option<(Field, ())>) =
                    match map.next_key()? {
                        Some(Field::date) => (map.next_value()?, map.next_entry()?),
                        Some(key) => (None, Some((key, ()))), //Some(key) => (None, Some((key, map.next_value()?))),
                        None => (None, None),
                    };

                if let Some((field, _)) = next_entry {
                    return Err(MapAcc::Error::unknown_field(field.into(), &[]));
                }

                Ok(VaryingParametersInfo {
                    n,
                    k,
                    info,
                    ballot_chaining,
                    date: opt_date.unwrap_or_default(),
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("VaryingParameters", FIELDS, VaryingParametersInfoVisitor)
    }
}

crate::impl_validatable_validated! {
    src: VaryingParametersInfo, produce_resource => EgResult<VaryingParameters> {
        let VaryingParametersInfo {
            n,
            k,
            info,
            ballot_chaining,
            date,
        } = src;

        //----- Validate `n`.

        // `n` must be greater than or equal to 1
        // Guaranteed by `GuardianIndex`.

        //----- Validate `k`.

        // `k` must be greater than or equal to 1
        // Guaranteed by `GuardianIndex`.

        // `k` must be less than or equal to `n`
        EgError::unless(
            k <= n,
            || EgValidateError::from(format!("k={k} <= n={n}")))?;

        //----- Validate `info`.

        //? TODO

        //----- Validate `ballot_chaining`.

        //? TODO

        //----- Validate `date`.

        //? TODO

        //----- Construct the object from the validated data.

        let self_ = VaryingParameters {
            n,
            k,
            info,
            ballot_chaining,
            date,
        };

        //----- Return the fully constructed and validated `VaryingParameters` object.

        Ok(self_)
    }
}

impl From<VaryingParameters> for VaryingParametersInfo {
    /// Convert from VaryingParameters back to a VaryingParametersInfo for re-validation.
    fn from(src: VaryingParameters) -> Self {
        let VaryingParameters {
            n,
            k,
            info,
            ballot_chaining,
            date,
        } = src;

        Self {
            n,
            k,
            info,
            ballot_chaining,
            date,
        }
    }
}

/// The election manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaryingParameters {
    n: GuardianIndex,
    k: GuardianIndex,
    info: String,
    ballot_chaining: BallotChaining,
    date: String,
}

impl VaryingParameters {
    /// Number of guardians.
    pub fn n(&self) -> GuardianIndex {
        self.n
    }

    /// Decryption quorum threshold value.
    pub fn k(&self) -> GuardianIndex {
        self.k
    }

    /// Jurisdictional information string. This can be used to specify a location.
    pub fn info(&self) -> &str {
        &self.info
    }

    /// Ballot chaining.
    pub fn ballot_chaining(&self) -> BallotChaining {
        self.ballot_chaining
    }

    /// Date. Optional, can be empty.
    /// Consider using [RFC 3339](https://datatracker.ietf.org/doc/rfc3339/) or "ISO 8601" format.
    pub fn date(&self) -> &str {
        &self.date
    }

    /// Iterates over the valid guardian indices, `1 <= ix <= [VaryingParameters::n`].
    pub fn each_guardian_ix(&self) -> impl Iterator<Item = GuardianIndex> {
        GuardianIndex::iter_range_inclusive(GuardianIndex::MIN, self.n)
    }
}

crate::impl_knows_friendly_type_name! { VaryingParameters }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { VaryingParameters, VaryingParameters }

impl SerializableCanonical for VaryingParameters {}

static_assertions::assert_impl_all!(VaryingParametersInfo: crate::validatable::Validatable);
static_assertions::assert_impl_all!(VaryingParameters: crate::validatable::Validated);
