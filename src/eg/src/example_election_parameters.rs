// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use crate::{
    election_parameters::ElectionParameters, fixed_parameters::FixedParameters,
    standard_parameters::STANDARD_PARAMETERS, varying_parameters::VaryingParameters,
};

/// An example ElectionParameters object, based on the standard parameters.
pub fn example_election_parameters() -> ElectionParameters {
    let fixed_parameters: FixedParameters = (*STANDARD_PARAMETERS).clone();

    let varying_parameters = VaryingParameters {
        n: 5,
        k: 3,
        date: "2022-11-08".to_string(),
        info: "General Election 2022".to_string(),
    };

    ElectionParameters {
        fixed_parameters,
        varying_parameters,
    }
}

pub fn user_study_parameters() -> ElectionParameters {
    let fixed_parameters: FixedParameters = (*STANDARD_PARAMETERS).clone();

    let varying_parameters = VaryingParameters {
        n: 1,
        k: 1,
        date: "2023-08-01".to_string(),
        info: "ElectionGuard User Study".to_string(),
    };

    ElectionParameters {
        fixed_parameters,
        varying_parameters,
    }
}
