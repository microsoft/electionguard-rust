// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(clippy::needless_lifetimes)] //? TODO: Remove temp development code
#![allow(clippy::absurd_extreme_comparisons)] //? TODO: Remove temp development code
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

//! This module provides types representing the fixed parameters.

use anyhow::{Context, Result, anyhow, bail, ensure};
//use either::Either;
//use rand::{distr::Uniform, Rng, RngCore};
//use static_assertions::{assert_obj_safe, assert_impl_all, assert_cfg, const_assert};
use tracing::{
    debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span,
    warn,
};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use util::{
    algebra::{Group, ScalarField},
    algebra_utils::{cnt_bits_repr, leading_ones},
    csrng::Csrng,
};

use crate::{
    eg::Eg,
    egds_version::{
        ElectionGuard_DesignSpecification_Version,
        ElectionGuard_DesignSpecification_Version_Qualifier, ElectionGuard_FixedParameters_Kind,
    },
    errors::EgError,
    resource::{
        ElectionDataObjectId as EdoId, Resource, ResourceFormat, ResourceId, ResourceIdFormat,
    },
    resource::{ProduceResource, ProduceResourceExt},
    serializable::{SerializableCanonical, SerializablePretty},
    validatable::{Validatable, Validated},
};

//=================================================================================================|

#[allow(non_upper_case_globals)]
const RID_FixedParameters: ResourceId = ResourceId::ElectionDataObject(EdoId::FixedParameters);

#[allow(non_upper_case_globals)]
const RIDFMT_FixedParameters_ConcreteType: ResourceIdFormat = ResourceIdFormat {
    rid: RID_FixedParameters,
    fmt: ResourceFormat::ConcreteType,
};

#[allow(non_upper_case_globals)]
const RIDFMT_FixedParameters_ValidatedEdo: ResourceIdFormat = ResourceIdFormat {
    rid: RID_FixedParameters,
    fmt: ResourceFormat::ValidElectionDataObject,
};

//=================================================================================================|

// "Nothing up my sleeve" numbers for use in fixed parameters.
#[allow(non_camel_case_types)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize
)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Info for constructing a [`FixedParameters`] through validation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct FixedParametersInfo {
    /// Version of the ElectionGuard Design Specification to which these parameters conform.
    /// E.g., `Some([2, 1])` for v2.1.
    /// `None` means the parameters may not conform to any version of the ElectionGuard spec.
    #[serde(
        rename = "ElectionGuard_Design_Specification_version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub opt_egds_version: Option<ElectionGuard_DesignSpecification_Version>,

    /// Parameters used to generate the fixed parameters.
    pub generation_parameters: FixedParameterGenerationParameters,

    /// Prime field `Z_q`.
    pub field: ScalarField,

    /// Group `Z_p^r` of the same order as `Z_q` including generator `g`.
    pub group: Group,
}

crate::impl_knows_friendly_type_name! { FixedParametersInfo }

crate::impl_Resource_for_simple_ElectionDataObjectId_info_type! { FixedParametersInfo, FixedParameters }

impl SerializableCanonical for FixedParametersInfo {}

impl FixedParametersInfo {
    pub fn new(
        opt_egds_version: Option<ElectionGuard_DesignSpecification_Version>,
        generation_parameters: FixedParameterGenerationParameters,
        field: ScalarField,
        group: Group,
    ) -> FixedParametersInfo {
        FixedParametersInfo {
            opt_egds_version,
            generation_parameters,
            field,
            group,
        }
    }
}

impl<'de> serde::Deserialize<'de> for FixedParametersInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use strum::VariantNames;

        #[derive(serde::Deserialize, VariantNames)]
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
                let (opt_egds_version, next_entry): (
                    Option<ElectionGuard_DesignSpecification_Version>,
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
                    opt_egds_version,
                    generation_parameters,
                    field,
                    group,
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("FixedParameters", FIELDS, FixedParametersInfoVisitor)
    }
}

crate::impl_validatable_validated! {
    fixed_parameters_info: FixedParametersInfo, produce_resource => EgResult<FixedParameters> {
        use ElectionGuard_DesignSpecification_Version as EgdsVersion;
        use ElectionGuard_DesignSpecification_Version_Qualifier as EgdsVersionQualifier;
        use ElectionGuard_FixedParameters_Kind as FPKind;

        let standard_params_info = crate::standard_parameters::make_standard_parameters_info();

        let Some(egds_version_from_standard_params) = standard_params_info.opt_egds_version.clone() else {
            return Err(EgValidateError::Str("Standard parameters missing egds_version").into());
        };

        debug!("StandardParameters EGDS version: {egds_version_from_standard_params}");
        debug!("FixedParametersInfo EGDS version: {:?}", fixed_parameters_info.opt_egds_version);

        assert_eq!(
            egds_version_from_standard_params.qualifier,
            EgdsVersionQualifier::Released_Specification_Version );

        assert_eq!(egds_version_from_standard_params.fixed_parameters_kind, FPKind::Standard_Parameters );

        let mut require_that_fixed_parameters_exactly_match_standard_parameters = true;
        let mut toy_parameters_permitted = false;

        // If `fixed_parameters_info` carries EGDS version info...
        if let Some(ref egds_version_from_fp_info) = fixed_parameters_info.opt_egds_version {

            // If `fixed_parameters_info` does not claim to match a released specification and standard parameters,
            // then consider relaxing that requirement.
            match egds_version_from_fp_info.qualifier {
                EgdsVersionQualifier::Released_Specification_Version => {
                    debug_assert!(require_that_fixed_parameters_exactly_match_standard_parameters);
                }
                EgdsVersionQualifier::Nonstandard_Specification(_) => {
                    if cfg!(feature = "eg-allow-nonstandard-egds-version") {
                        require_that_fixed_parameters_exactly_match_standard_parameters = false;
                    } else {
                        return Err(EgError::NonstandardEgdsVersionNotSupported {
                            egds_version_from_fp_info: egds_version_from_fp_info.clone(),
                        });
                    }
                }
            }

            // If `fixed_parameters_info` does not claim to match a released specification and standard parameters,
            // then consider relaxing that requirement.
            match egds_version_from_fp_info.fixed_parameters_kind {
                ElectionGuard_FixedParameters_Kind::Toy_Parameters => {
                    if cfg!(feature = "eg-allow-toy-parameters") {
                        toy_parameters_permitted = true;
                    } else {
                        return Err(EgError::ToyParametersNotSupported {
                            egds_version_from_fp_info: egds_version_from_fp_info.clone(),
                        });
                    }
                }
                _ => {
                    debug_assert!(!toy_parameters_permitted);
                }
            }
        };

        // Compare the fixed_parametrs_info to the standard parameters.
        let fixed_parameters_do_exactly_match_standard_parameters = fixed_parameters_info == standard_params_info;

        // If we require that the fixed parameters match exactly the standard parameters, but they didn't, return an error.
        if require_that_fixed_parameters_exactly_match_standard_parameters && ! fixed_parameters_do_exactly_match_standard_parameters {
            let e = if let Some(egds_version_from_fp_info) = fixed_parameters_info.opt_egds_version {
                EgError::FixedParametersDoNotMatchStatedElectionGuardDesignSpecificationVersion {
                    egds_version_from_fp_info,
                    egds_version_from_standard_params,
                }
            } else {
                EgError::FixedParametersDoNotDeclareAnElectionGuardDesignSpecificationVersionOrMatchStandardParams {
                    egds_version_from_standard_params,
                }
            };
            return Err(e);
        }

        // Perform the expensive validation checks on the supplied `FixedParameters` if
        // they did not match exactly our defined standard parameters.
        let perform_expensive_fixed_parameters_validation_checks = ! fixed_parameters_do_exactly_match_standard_parameters;

        let FixedParametersInfo {
            opt_egds_version,
            generation_parameters,
            field,
            group,
        } = fixed_parameters_info;

        if perform_expensive_fixed_parameters_validation_checks {
            info!("Performing expensive validation checks on FixedParameters");

            if !field.is_valid(produce_resource.csrng()) {
                return Err(EgValidateError::Other("The field order q is not prime.".to_string()).into());
            }

            if !group.is_valid(produce_resource.csrng()) {
                return Err(EgValidateError::Other("The group is invalid.".to_string()).into());
            }

            if !group.matches_field(&field) {
                return Err(EgValidateError::Other("The orders of group and field are different.".to_string()).into());
            }

            let cnt_bits_field_order = cnt_bits_repr(&field.order());
            if    cnt_bits_field_order != generation_parameters.q_bits_total
               || (cnt_bits_field_order < 250 && !toy_parameters_permitted)
            {
                return Err(EgValidateError::Other("Fixed parameters: order q wrong number of bits.".to_string()).into());
            }

            let cnt_bits_group_modulus = cnt_bits_repr(&group.modulus());
            if    cnt_bits_group_modulus != generation_parameters.p_bits_total
               || (cnt_bits_group_modulus < 4000 && !toy_parameters_permitted)
            {
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
        }

        //----- Construct the validated ElectionDataObject.

        let self_ = Self {
            opt_egds_version,
            generation_parameters,
            field,
            group,
        };

        Ok(self_)
    }
}

impl From<FixedParameters> for FixedParametersInfo {
    fn from(src: FixedParameters) -> Self {
        let FixedParameters {
            opt_egds_version,
            generation_parameters,
            field,
            group,
        } = src;

        Self {
            opt_egds_version,
            generation_parameters,
            field,
            group,
        }
    }
}

/// The fixed parameters define the used field and group.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct FixedParameters {
    /// Version of the ElectionGuard Design Specification to which these parameters conform.
    /// E.g., `Some([2, 1])` for v2.1.
    /// `None` means the parameters may not conform to any version of the ElectionGuard spec.
    #[serde(
        rename = "ElectionGuard_Design_Specification_version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    opt_egds_version: Option<ElectionGuard_DesignSpecification_Version>,

    /// Parameters used to generate the fixed parameters.
    generation_parameters: FixedParameterGenerationParameters,

    /// Prime field `Z_q`.
    field: ScalarField,

    /// Group `Z_p^r` of the same order as `Z_q` including generator `g`.
    group: Group,
}

impl FixedParameters {
    pub fn opt_egds_version(&self) -> &Option<ElectionGuard_DesignSpecification_Version> {
        &self.opt_egds_version
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

crate::impl_knows_friendly_type_name! { FixedParameters }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { FixedParameters, FixedParameters }

impl SerializableCanonical for FixedParameters {}

static_assertions::assert_impl_all!(FixedParametersInfo: crate::validatable::Validatable);
static_assertions::assert_impl_all!(FixedParameters: crate::validatable::Validated);

// Unit tests for the FixedParameters.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod t {
    use std::io::Cursor;

    use super::*;
    use crate::{
        fixed_parameters,
        resource_id::ElectionDataObjectId,
        serializable::{SerializableCanonical, SerializablePretty},
    };

    #[test]
    fn t1() {
        let eg = Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::fixed_parameters::t::t1",
        );
        let eg = eg.as_ref();

        async_global_executor::block_on(async {
            let fixed_parameters_ridfmt =
                ElectionDataObjectId::FixedParameters.validated_type_ridfmt();

            let result = eg
                .produce_resource_downcast_no_src::<FixedParameters>(&fixed_parameters_ridfmt)
                .await;

            if let Err(e) = &result {
                eprintln!("Err(e): {e:#?}");
                eprintln!("eg: {eg:#?}");
            }

            let fixed_parameters = result.unwrap();
            let fixed_parameters = fixed_parameters.as_ref();

            let mut buf = Cursor::new(vec![0u8; 0]);
            fixed_parameters.to_stdiowrite_pretty(&mut buf).unwrap();

            let json_pretty = {
                let mut buf = Cursor::new(vec![0u8; 0]);
                buf.into_inner()
            };
            assert!(json_pretty.len() > 6);
            assert_eq!(*json_pretty.last().unwrap(), b'\n');
            let s: &str = std::str::from_utf8(json_pretty.as_slice()).unwrap();
            eprintln!("vvvvvvvvvvvvvv pretty vvvvvvvvvvvvvv");
            eprintln!("{s}");
            eprintln!("^^^^^^^^^^^^^^ pretty ^^^^^^^^^^^^^^");
        });
    }
}
