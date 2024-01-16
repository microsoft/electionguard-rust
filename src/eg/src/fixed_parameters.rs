// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{ensure, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use util::{
    algebra::{Group, ScalarField, group_matches_field},
    csprng::Csprng,
    integer_util::cnt_bits_repr,
    prime::BigUintPrime,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedParameterGenerationParameters {
    pub q_bits_total: usize,
    pub p_bits_total: usize,
    pub p_bits_msb_fixed_1: usize,
    pub p_middle_bits_source: NumsNumber,
    pub p_bits_lsb_fixed_1: usize,
}

// Released prereleased.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OfficialReleaseKind {
    Release,
    Prerelease,
}

// Released prereleased.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficialVersion {
    pub version: [usize; 2],
    pub release: OfficialReleaseKind,
}

// Design specification version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElectionGuardDesignSpecificationVersion {
    /// Officially-released "ElectionGuard Design Specification" version.
    /// Which may be an official pre-release.
    Official(OfficialVersion),

    /// Some other specification and version.
    Other(String),
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedParameters {
    /// Version of the ElectionGuard Design Specification to which these parameters conform.
    /// E.g., `Some([2, 0])` for v2.0 and `Some([1, 55])` for v1.55.
    /// `None` means the parameters may not conform to any version of the ElectionGuard spec.
    #[serde(
        rename = "ElectionGuard_Design_Specification",
        skip_serializing_if = "Option::is_none"
    )]
    pub opt_ElectionGuard_Design_Specification: Option<ElectionGuardDesignSpecificationVersion>,

    /// Parameters used to generate the parameters.
    pub generation_parameters: FixedParameterGenerationParameters,

    /// Prime field
    pub field: ScalarField,

    /// Group
    pub group: Group,

    /// Prime modulus.
    pub p: BigUintPrime,

    /// Subgroup order.
    pub q: BigUintPrime,

    /// Cofactor of q in p − 1.
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub r: BigUint,

    /// Subgroup generator.
    #[serde(
        serialize_with = "util::biguint_serde::biguint_serialize",
        deserialize_with = "util::biguint_serde::biguint_deserialize"
    )]
    pub g: BigUint,
}

impl FixedParameters {

    /// Verifies that the `FixedParameters` meet some basic validity requirements.
    #[allow(clippy::nonminimal_bool)]
    pub fn validate(&self, csprng: &mut Csprng) -> Result<()> {
        
        let field = &self.field;
        let group = &self.group;

        ensure!(field.is_valid(csprng), "The field order q is not prime!");
        ensure!(group.is_valid(csprng), "The group is invalid!");
        ensure!(group_matches_field(group, field), "The orders of group and field are different!");

        ensure!(
            cnt_bits_repr(&field.order()) == self.generation_parameters.q_bits_total,
            "Fixed parameters: order q wrong number of bits"
        );
        ensure!(
            cnt_bits_repr(&group.modulus()) == self.generation_parameters.p_bits_total,
            "Fixed parameters: modulus p wrong number of bits"
        );

        //TODO Maybe check that the parameters are consistent with the spec version
        //TODO verify p_bits_msb_fixed_1
        //TODO verify p_middle_bits_source
        //TODO verify p_bits_lsb_fixed_1

        Ok(())
    }
}
