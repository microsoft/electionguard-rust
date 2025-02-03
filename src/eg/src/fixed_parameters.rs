// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

//! This module provides fixed parameter type.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use util::{
    algebra::{Group, ScalarField},
    algebra_utils::{cnt_bits_repr, leading_ones},
    csrng::Csrng,
};

use crate::{
    eg::Eg,
    resource::{
        ElectionDataObjectId as EdoId, Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    serializable::{SerializableCanonical, SerializablePretty},
    validatable::{Validatable, Validated},
};

// "Nothing up my sleeve" numbers for use in fixed parameters.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NumsNumber {
    /// The Euler-Mascheroni constant γ =~ 0.577215664901532...
    /// Binary expansion: (0.)1001001111000100011001111110...
    /// <https://oeis.org/A104015>
    ///
    /// This was used in versions of the spec prior to v2.0.
    Euler_Mascheroni_constant,

    /// The natural logarithm of 2.
    /// Binary expansion: (0.)1011000101110010000101111111...
    ///                          B   1   7   2   1   7   F...
    /// <https://oeis.org/A068426>
    ///
    /// This is used starting in spec version v2.0.
    ln_2,
}

/// Properties of the fixed parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedParameterGenerationParameters {
    /// Number of bits of the field order `q`
    pub q_bits_total: usize,

    /// Number of bits of the group modulus `p`
    pub p_bits_total: usize,

    // Number of leading `1` valued bits of `p`
    pub p_bits_msb_fixed_1: usize,

    // Source of the middle bits of `p`
    pub p_middle_bits_source: Option<NumsNumber>,

    // Number of trailing `1` valued bits of `p`
    pub p_bits_lsb_fixed_1: usize,
}

// Design specification version.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    PartialOrd,
    Ord
)]
pub struct ElectionGuardDesignSpecificationVersion {
    pub number: [u32; 2],
}

impl SerializableCanonical for ElectionGuardDesignSpecificationVersion {}

crate::impl_knows_friendly_type_name! { ElectionGuardDesignSpecificationVersion }

crate::impl_Resource_for_simple_ResourceId_type! {
    ElectionGuardDesignSpecificationVersion,
    ElectionGuardDesignSpecificationVersion, ConcreteType
}

/// Info for constructing a [`FixedParameters`] through validation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FixedParametersInfo {
    /// Version of the ElectionGuard Design Specification to which these parameters conform.
    /// E.g., `Some([2, 1])` for v2.1.
    /// `None` means the parameters may not conform to any version of the ElectionGuard spec.
    #[serde(
        rename = "ElectionGuard_Design_Specification_version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub opt_eg_design_specification_version: Option<ElectionGuardDesignSpecificationVersion>,

    /// Parameters used to generate the fixed parameters.
    pub generation_parameters: FixedParameterGenerationParameters,

    /// Prime field `Z_q`.
    pub field: ScalarField,

    /// Group `Z_p^r` of the same order as `Z_q` including generator `g`.
    pub group: Group,

    /// Refers to this object as a [`Resource`].
    // TODO this can go away
    #[serde(skip)]
    ridfmt: ResourceIdFormat,
}

impl FixedParametersInfo {
    pub fn new(
        opt_eg_design_specification_version: Option<ElectionGuardDesignSpecificationVersion>,
        generation_parameters: FixedParameterGenerationParameters,
        field: ScalarField,
        group: Group,
    ) -> FixedParametersInfo {
        let edoid = EdoId::FixedParameters;
        let ridfmt = edoid.info_type_ridfmt();

        FixedParametersInfo {
            opt_eg_design_specification_version,
            generation_parameters,
            field,
            group,
            ridfmt,
        }
    }
}

impl<'de> Deserialize<'de> for FixedParametersInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use strum::VariantNames;

        #[derive(Deserialize, VariantNames)]
        #[serde(field_identifier)]
        #[allow(non_camel_case_types)]
        enum Field {
            eg_design_specification_version,
            generation_parameters,
            field,
            group,
        }

        struct FixedParametersInfoVisitor;

        impl<'de> Visitor<'de> for FixedParametersInfoVisitor {
            type Value = FixedParametersInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("FixedParametersInfo")
            }

            fn visit_map<MapAcc>(
                self,
                mut map: MapAcc,
            ) -> Result<FixedParametersInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let (opt_eg_design_specification_version, next_entry): (
                    Option<ElectionGuardDesignSpecificationVersion>,
                    _,
                ) = match map.next_key()? {
                    Some(Field::eg_design_specification_version) => {
                        (Some(map.next_value()?), map.next_entry()?)
                    }
                    Some(key) => (None, Some((key, map.next_value()?))),
                    None => (None, None),
                };

                let Some((Field::generation_parameters, generation_parameters)) = next_entry else {
                    return Err(MapAcc::Error::missing_field("generation_parameters"));
                };

                let Some((Field::field, field)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field("field"));
                };

                let Some((Field::group, group)) = map.next_entry()? else {
                    return Err(MapAcc::Error::missing_field("group"));
                };

                let edoid = EdoId::FixedParameters;
                let ridfmt = edoid.info_type_ridfmt();

                Ok(FixedParametersInfo {
                    opt_eg_design_specification_version,
                    generation_parameters,
                    field,
                    group,
                    ridfmt,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("FixedParameters", FIELDS, FixedParametersInfoVisitor)
    }
}

//? TODO do we want SerializableCanonical for non-validated `Info` types?
impl SerializableCanonical for FixedParametersInfo {}

crate::impl_knows_friendly_type_name! { FixedParametersInfo }

impl Resource for FixedParametersInfo {
    fn ridfmt(&self) -> &ResourceIdFormat {
        let ridfmt_expected = EdoId::FixedParameters.info_type_ridfmt();
        debug_assert_eq!(self.ridfmt, ridfmt_expected);
        &self.ridfmt
    }
}

crate::impl_validatable_validated! {
    src: FixedParametersInfo, eg => EgResult<FixedParameters> {
        let FixedParametersInfo {
            opt_eg_design_specification_version,
            generation_parameters,
            field,
            group,
            ridfmt,
        } = src;

        if !field.is_valid(eg.csrng()) {
            return Err(EgValidateError::Other("The field order q is not prime.".to_string()).into());
        }

        if !group.is_valid(eg.csrng()) {
            return Err(EgValidateError::Other("The group is invalid.".to_string()).into());
        }

        if !group.matches_field(&field) {
            return Err(EgValidateError::Other("The orders of group and field are different.".to_string()).into());
        }

        if cnt_bits_repr(&field.order()) != generation_parameters.q_bits_total {
            return Err(EgValidateError::Other("Fixed parameters: order q wrong number of bits.".to_string()).into());
        }

        if cnt_bits_repr(&group.modulus()) != generation_parameters.p_bits_total {
            return Err(EgValidateError::Other("Fixed parameters: modulus p wrong number of bits.".to_string()).into());
        }

        let leading_ones = leading_ones(group.modulus()) as usize;
        if leading_ones < generation_parameters.p_bits_msb_fixed_1 {
            return Err(EgValidateError::Other("Too few leading ones.".to_string()).into());
        }

        let trailing_ones = group.modulus().trailing_ones() as usize;
        if trailing_ones < generation_parameters.p_bits_lsb_fixed_1 {
            return Err(EgValidateError::Other("Too few trailing ones.".to_string()).into());
        }

        //TODO Maybe check that the parameters are consistent with the spec version?

        //TODO verify p_middle_bits_source

        let ridfmt_expected = EdoId::FixedParameters.info_type_ridfmt();
        if ridfmt != ridfmt_expected {
            let s = format!("Expecting: `{ridfmt_expected}`, got: `{ridfmt}`");
            return Err(EgValidateError::Other(s))?;
        }

        //----- Construct the validated ElectionDataObject.

        let self_ = Self {
            opt_eg_design_specification_version,
            generation_parameters,
            field,
            group,
            ridfmt,
        };

        Ok(self_)
    }
}

impl From<FixedParameters> for FixedParametersInfo {
    fn from(src: FixedParameters) -> Self {
        let FixedParameters {
            opt_eg_design_specification_version,
            generation_parameters,
            field,
            group,
            ridfmt,
        } = src;

        debug_assert_eq!(ridfmt, EdoId::FixedParameters.validated_type_ridfmt());

        Self {
            opt_eg_design_specification_version,
            generation_parameters,
            field,
            group,
            ridfmt: EdoId::FixedParameters.info_type_ridfmt(),
        }
    }
}

/// The fixed parameters define the used field and group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FixedParameters {
    /// Version of the ElectionGuard Design Specification to which these parameters conform.
    /// E.g., `Some([2, 1])` for v2.1.
    /// `None` means the parameters may not conform to any version of the ElectionGuard spec.
    #[serde(
        rename = "ElectionGuard_Design_Specification_version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    opt_eg_design_specification_version: Option<ElectionGuardDesignSpecificationVersion>,

    /// Parameters used to generate the fixed parameters.
    generation_parameters: FixedParameterGenerationParameters,

    /// Prime field `Z_q`.
    field: ScalarField,

    /// Group `Z_p^r` of the same order as `Z_q` including generator `g`.
    group: Group,

    /// Refers to this object as a [`Resource`].
    // TODO this can go away
    #[serde(skip)]
    ridfmt: ResourceIdFormat,
}

impl FixedParameters {
    pub fn opt_eg_design_specification_version(
        &self,
    ) -> Option<ElectionGuardDesignSpecificationVersion> {
        self.opt_eg_design_specification_version
    }

    pub fn generation_parameters(&self) -> &FixedParameterGenerationParameters {
        &self.generation_parameters
    }

    pub fn field(&self) -> &ScalarField {
        &self.field
    }

    pub fn group(&self) -> &Group {
        &self.group
    }
}

impl SerializableCanonical for FixedParameters {}

crate::impl_knows_friendly_type_name! { FixedParameters }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { FixedParameters, FixedParameters }

static_assertions::assert_impl_all!(FixedParametersInfo: crate::validatable::Validatable);
static_assertions::assert_impl_all!(FixedParameters: crate::validatable::Validated);
