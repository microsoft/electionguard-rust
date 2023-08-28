// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use crate::{
    election_parameters::ElectionParameters,
    fixed_parameters::FixedParameters,
    guardian::GuardianIndex,
    standard_parameters::STANDARD_PARAMETERS,
    varying_parameters::{BallotChaining, VaryingParameters},
};

/// An example ElectionParameters object, based on the standard parameters.
pub fn example_election_parameters() -> ElectionParameters {
    let fixed_parameters: FixedParameters = (*STANDARD_PARAMETERS).clone();

    let n = 5;
    let k = 3;

    // `unwrap()` is justified here because these values are fixed.
    #[allow(clippy::unwrap_used)]
    let n = GuardianIndex::from_one_based_index(n).unwrap();
    #[allow(clippy::unwrap_used)]
    let k = GuardianIndex::from_one_based_index(k).unwrap();

    let varying_parameters = VaryingParameters {
        n,
        k,
        date: "2023-05-02".to_string(),
        info: "The United Realms of Imaginaria, General Election".to_string(),
        ballot_chaining: BallotChaining::Prohibited,
    };

    ElectionParameters {
        fixed_parameters,
        varying_parameters,
    }
}
