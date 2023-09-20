// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use anyhow::{ensure, Context, Result};

use crate::{
    election_parameters::ElectionParameters, guardian::GuardianIndex,
    guardian_secret_key::CoefficientCommitments,
};

/// Trait for read access to data from a `GuardianPublicKey`, which is common to
/// both `GuardianPublicKey` and `GuardianSecretKey`.
pub trait GuardianPublicKeyInfo {
    /// Guardian number, 1 <= i <= n.
    fn i(&self) -> GuardianIndex;

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
    let n = varying_parameters.n.as_quantity();
    let k = varying_parameters.k.as_quantity();

    let i = gpki.i().get_one_based_usize();
    ensure!(
        1 <= i && i <= n,
        "Guardian number i={i} is not in the range 1 <= i <= n={n}"
    );

    if let Some(name) = &gpki.opt_name() {
        ensure!(
            !name.contains('\n'),
            "Guardian name must not contain a newline"
        );
    }

    let coefficient_commitments_len = gpki.coefficient_commitments().0.len();
    ensure!(
        coefficient_commitments_len == k,
        "Expected k={k} coefficient commitments, found {coefficient_commitments_len}"
    );

    for (ix, coefficient_commitment) in gpki.coefficient_commitments().0.iter().enumerate() {
        coefficient_commitment
            .validate(election_parameters)
            .with_context(|| format!("Coefficient commitment {ix} is invalid"))?;
    }

    Ok(())
}
