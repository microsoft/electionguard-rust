// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

//! This module provides fixed parameter type.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use util::{
    algebra::{Group, ScalarField},
    algebra_utils::{cnt_bits_repr, leading_ones},
    csprng::Csprng,
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
    /// This is used in spec version to v2.0.
    ln_2,
}

/// Properties of the fixed parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedParameterGenerationParameters {
    /// number of bits of the field order `q`
    pub q_bits_total: usize,

    /// number of bits of the group modulus `p`
    pub p_bits_total: usize,

    // number of leading bits set to 1 for `p`
    pub p_bits_msb_fixed_1: usize,

    // source of the middle bits
    pub p_middle_bits_source: Option<NumsNumber>,

    // number of trailing bits set to 1 for `p`
    pub p_bits_lsb_fixed_1: usize,
}

// Design specification version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ElectionGuardDesignSpecificationVersion {
    pub number: [u32; 2],
}

/// The fixed parameters define the used field and group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedParameters {
    /// Version of the ElectionGuard Design Specification to which these parameters conform.
    /// E.g., `Some([2, 0])` for v2.0 and `Some([1, 55])` for v1.55.
    /// `None` means the parameters may not conform to any version of the ElectionGuard spec.
    #[serde(
        rename = "ElectionGuard_Design_Specification_version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub opt_eg_design_specification_version: Option<ElectionGuardDesignSpecificationVersion>,

    /// Parameters used to generate the parameters.
    pub generation_parameters: FixedParameterGenerationParameters,

    /// Prime field `Z_q`.
    pub field: ScalarField,

    /// Group `Z_p^r` of the same order as `Z_q` including generator `g`.
    pub group: Group,
}

impl FixedParameters {
    /// Verifies that the `FixedParameters` meet some basic validity requirements.
    pub fn validate(&self, csprng: &mut Csprng) -> Result<()> {
        let field = &self.field;
        let group = &self.group;

        ensure!(field.is_valid(csprng), "The field order q is not prime!");
        ensure!(group.is_valid(csprng), "The group is invalid!");
        ensure!(
            group.matches_field(field),
            "The orders of group and field are different!"
        );

        ensure!(
            cnt_bits_repr(&field.order()) == self.generation_parameters.q_bits_total,
            "Fixed parameters: order q wrong number of bits"
        );
        ensure!(
            cnt_bits_repr(&group.modulus()) == self.generation_parameters.p_bits_total,
            "Fixed parameters: modulus p wrong number of bits"
        );

        let leading_ones = leading_ones(group.modulus()) as usize;
        ensure!(leading_ones >= self.generation_parameters.p_bits_msb_fixed_1);

        let trailing_ones = group.modulus().trailing_ones() as usize;
        ensure!(trailing_ones >= self.generation_parameters.p_bits_lsb_fixed_1);

        //TODO Maybe check that the parameters are consistent with the spec version
        //TODO verify p_middle_bits_source

        Ok(())
    }
}
