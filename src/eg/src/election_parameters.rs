// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use crate::{fixed_parameters::FixedParameters, varying_parameters::VaryingParameters};

#[derive(Debug)]
pub struct ElectionParameters {
    /// The fixed ElectionGuard parameters that apply to all elections.
    pub fixed_parameters: FixedParameters,

    /// The parameters for a specific election.
    pub varying_parameters: VaryingParameters,
}
