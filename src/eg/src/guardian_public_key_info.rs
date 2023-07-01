// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::num::NonZeroU16;

use anyhow::{ensure, Context, Result};

use crate::{election_parameters::ElectionParameters, guardian_secret_key::CoefficientCommitments};

/// Trait for read access to data from a `GuardianPublicKey`, which is common to
/// both `GuardianPublicKey` and `GuardianSecretKey`.
pub trait GuardianPublicKeyInfo {
    /// Guardian number, 1 <= i <= n.
    fn i(&self) -> NonZeroU16;

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    fn opt_name(&self) -> &Option<String>;

    /// "Published" polynomial coefficient commitments.
    fn coefficient_commitments(&self) -> &CoefficientCommitments;
}

/// Verifies that the thing implementing `GuardianPublicKeyInfo` is well-formed and conforms
/// to the election parameters.
/// Useful after deserialization.
pub(crate) fn validate_guardian_public_key_info(
    gpki: &dyn GuardianPublicKeyInfo,
    election_parameters: &ElectionParameters,
) -> Result<()> {
    let varying_parameters = &election_parameters.varying_parameters;
    let n: usize = varying_parameters.n.into();
    let k: usize = varying_parameters.k.into();

    ensure!(
        varying_parameters.is_valid_guardian_i(gpki.i().get()),
        "Guardian number i={} is not in the range 1 <= i <= n={n}",
        gpki.i()
    );

    if let Some(name) = &gpki.opt_name() {
        ensure!(
            !name.contains('\n'),
            "Guardian name must not contain a newline"
        );
    }

    ensure!(
        gpki.coefficient_commitments().0.len() == k,
        "Expected k={k} coefficient commitments, found {}",
        gpki.coefficient_commitments().0.len()
    );

    for (ix, coefficient_commitment) in gpki.coefficient_commitments().0.iter().enumerate() {
        coefficient_commitment
            .validate(election_parameters)
            .with_context(|| format!("Coefficient commitment {ix} is invalid"))?;
    }

    Ok(())
}
