// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(clippy::assertions_on_constants)]
#![allow(clippy::expect_used)] // This is `cfg(feature = "eg-allow-test-data-generation")` code
#![allow(clippy::manual_assert)] // This is `cfg(feature = "eg-allow-test-data-generation")` code
#![allow(clippy::new_without_default)] // This is `cfg(feature = "eg-allow-test-data-generation")` code
#![allow(clippy::panic)] // This is `cfg(feature = "eg-allow-test-data-generation")` code
#![allow(clippy::unwrap_used)] // This is `cfg(feature = "eg-allow-test-data-generation")` code

use std::rc::Rc;

use either::Either;

use crate::{
    eg::Eg,
    election_parameters::{ElectionParameters, ElectionParametersInfo},
    errors::EgResult,
    guardian::GuardianIndex,
    validatable::Validated,
    varying_parameters::{BallotChaining, VaryingParametersInfo},
};

pub fn example_election_parameters(eg: &Eg) -> ElectionParameters {
    let n = 5;
    let k = 3;

    // Unwrap() is justified here because we test this function with these parameters extensively.
    #[allow(clippy::unwrap_used)]
    example_election_parameters2(eg, n, k).unwrap()
}

/// An example ElectionParameters object, based on the standard parameters.
pub fn example_election_parameters2(
    eg: &Eg,
    varying_parameter_n: u32,
    varying_parameter_k: u32,
) -> EgResult<ElectionParameters> {
    let fixed_parameters = crate::standard_parameters::make_standard_parameters(eg).unwrap();

    let n = GuardianIndex::try_from_one_based_index(varying_parameter_n)?;
    let k = GuardianIndex::try_from_one_based_index(varying_parameter_k)?;

    let varying_parameters_info = VaryingParametersInfo {
        n,
        k,
        date: "2023-05-02".to_string(),
        info: "The United Realms of Imaginaria, General Election".to_string(),
        ballot_chaining: BallotChaining::Prohibited,
    };

    let election_parameters_info = ElectionParametersInfo {
        fixed_parameters: Either::Right(Rc::new(fixed_parameters)),
        varying_parameters: Either::Left(Rc::new(varying_parameters_info)),
    };

    ElectionParameters::try_validate_from(election_parameters_info, eg)
}
