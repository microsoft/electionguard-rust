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
#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

use std::sync::Arc;

use anyhow::{Context, Result};
use either::*;
use serde::{Deserialize, Serialize};

use crate::{
    eg::Eg,
    errors::EgResult,
    fixed_parameters::{self, FixedParameters, FixedParametersInfo},
    resource::{ElectionDataObjectId, HasStaticResourceIdFormat, Resource, ResourceIdFormat},
    resource::{ProduceResource, ProduceResourceExt},
    serializable::SerializableCanonical,
    validatable::{Validatable, Validated},
    varying_parameters::{VaryingParameters, VaryingParametersInfo},
};

#[derive(Debug, Clone, Serialize)]
pub struct ElectionParametersInfo {
    /// The fixed ElectionGuard election_parameters that apply to all elections.
    pub fixed_parameters: Either<Arc<FixedParametersInfo>, Arc<FixedParameters>>,

    /// The election_parameters for a specific election.
    pub varying_parameters: Either<Arc<VaryingParametersInfo>, Arc<VaryingParameters>>,
}

crate::impl_knows_friendly_type_name! { ElectionParametersInfo }

crate::impl_Resource_for_simple_ElectionDataObjectId_info_type! { ElectionParametersInfo, ElectionParameters }

impl SerializableCanonical for ElectionParametersInfo {}

impl<'de> Deserialize<'de> for ElectionParametersInfo {
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
            fixed_parameters,
            varying_parameters,
        }

        struct ElectionParametersInfoVisitor;

        impl<'de> Visitor<'de> for ElectionParametersInfoVisitor {
            type Value = ElectionParametersInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("ElectionParametersInfo")
            }

            fn visit_map<MapAcc>(
                self,
                mut map: MapAcc,
            ) -> Result<ElectionParametersInfo, MapAcc::Error>
            where
                MapAcc: MapAccess<'de>,
            {
                let Some((Field::fixed_parameters, fixed_parameters_info)) = map.next_entry()?
                else {
                    return Err(MapAcc::Error::missing_field(Field::fixed_parameters.into()));
                };

                let Some((Field::varying_parameters, varying_parameters_info)) =
                    map.next_entry()?
                else {
                    return Err(MapAcc::Error::missing_field(
                        Field::varying_parameters.into(),
                    ));
                };

                Ok(ElectionParametersInfo {
                    fixed_parameters: Left(fixed_parameters_info),
                    varying_parameters: Left(varying_parameters_info),
                })
            }
        }

        const FIELDS: &[&str] = Field::VARIANTS;

        deserializer.deserialize_struct("ElectionParameters", FIELDS, ElectionParametersInfoVisitor)
    }
}

crate::impl_validatable_validated! {
    src: ElectionParametersInfo, produce_resource => EgResult<ElectionParameters> {
        let ElectionParametersInfo {
            fixed_parameters,
            varying_parameters,
        } = src;

        // Validate `FixedParameters`.
        let fixed_parameters = match fixed_parameters {
            Left(fixed_parameters_info) => {
                let fixed_parameters_info = Arc::unwrap_or_clone(fixed_parameters_info);
                let fixed_parameters = FixedParameters::try_validate_from(fixed_parameters_info, produce_resource)?;
                Arc::new(fixed_parameters)
            }
            Right(fixed_parameters) => fixed_parameters,
        };

        // Validate `VaryingParameters`.
        let varying_parameters = match varying_parameters {
            Left(varying_parameters_info) => {
                let varying_parameters = VaryingParameters::try_validate_from_arc(varying_parameters_info, produce_resource)?;
                Arc::new(varying_parameters)
            }
            Right(varying_parameters) => varying_parameters,
        };

        //----- Construct the validated ElectionDataObject.

        let self_ = Self {
            fixed_parameters,
            varying_parameters,
        };

        Ok(self_)
    }
}

impl From<ElectionParameters> for ElectionParametersInfo {
    /// Convert from ElectionParameters back to a ElectionParametersInfo for re-validation.
    fn from(src: ElectionParameters) -> Self {
        let ElectionParameters {
            fixed_parameters,
            varying_parameters,
        } = src;

        Self {
            fixed_parameters: Right(fixed_parameters),
            varying_parameters: Right(varying_parameters),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ElectionParameters {
    fixed_parameters: Arc<FixedParameters>,
    varying_parameters: Arc<VaryingParameters>,
}

impl ElectionParameters {
    pub fn fixed_parameters(&self) -> &FixedParameters {
        self.fixed_parameters.as_ref()
    }

    pub fn varying_parameters(&self) -> &VaryingParameters {
        self.varying_parameters.as_ref()
    }
}

crate::impl_knows_friendly_type_name! { ElectionParameters }

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { ElectionParameters, ElectionParameters }

impl SerializableCanonical for ElectionParameters {}
