// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

//! This module provides the [`GuardianPublicKeyInfo`] trait
//! which allows read access and validation of public key data.

use crate::{
    election_parameters::ElectionParameters, guardian::GuardianIndex,
    guardian_coeff_proof::CoefficientProof, guardian_secret_key::CoefficientCommitments,
};
use thiserror::Error;

/// Trait for read access to data from a [`GuardianPublicKey`], which is common to
/// both [`GuardianPublicKey`] and [`GuardianSecretKey`].
///
/// It also allows to validate both types of keys (cf. Verification `2` in Section `3.2.2`).
pub trait GuardianPublicKeyInfo {
    /// Guardian number, 1 <= i <= [`n`](crate::varying_parameters::VaryingParameters::n).
    fn i(&self) -> GuardianIndex;

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    fn opt_name(&self) -> &Option<String>;

    /// "Published" polynomial coefficient commitments.
    fn coefficient_commitments(&self) -> &CoefficientCommitments;

    /// Proofs of knowledge for secret coefficients.
    fn coefficient_proofs(&self) -> &[CoefficientProof];
}

/// Represents errors occurring during the validation of a public key.
#[derive(Error, Debug)]
pub enum PublicKeyValidationError {
    /// Occurs if the guardian's index is out of bounds.
    #[error("Guardian number i={i} is not in the range 1 <= i <= n={n}")]
    IndexOutOfRange { i: usize, n: usize },
    /// Occurs if the guardian's name contains a newline character.
    #[error("The guardian's name must not contain a newline.")]
    NameContainsNewLine,
    /// Occurs if the guardian's commitment vector is not of length [`k`](crate::varying_parameters::VaryingParameters::k).
    #[error("Expected k={k} coefficient commitments, found {c_len}")]
    InadequateNumberOfCommitments { k: usize, c_len: usize },
    /// Occurs if a coefficient proof is invalid.
    #[error("The proof for coefficient {j} is invalid.")]
    InvalidProof { j: usize },
}

/// Verifies that the thing implementing [`GuardianPublicKeyInfo`] is well-formed and conforms
/// to the election parameters.
///
/// The arguments are:
/// - `gpki` - the public key object
/// - `election_parameters` - the election parameters
///
/// This corresponds to Verification `2` in Section `3.2.2`. Useful after deserialization.
pub(crate) fn validate_guardian_public_key_info(
    gpki: &dyn GuardianPublicKeyInfo,
    election_parameters: &ElectionParameters,
) -> Result<(), PublicKeyValidationError> {
    let fixed_parameters = &election_parameters.fixed_parameters;

    let varying_parameters = &election_parameters.varying_parameters;
    let n = varying_parameters.n.as_quantity();
    let k = varying_parameters.k.as_quantity();

    let i = gpki.i().get_one_based_usize();
    if 1 > i || i > n {
        return Err(PublicKeyValidationError::IndexOutOfRange { i, n });
    }

    if let Some(name) = &gpki.opt_name() {
        if name.contains('\n') {
            return Err(PublicKeyValidationError::NameContainsNewLine);
        }
    }

    let c_len = gpki.coefficient_commitments().0.len();
    if c_len != k {
        return Err(PublicKeyValidationError::InadequateNumberOfCommitments { k, c_len });
    }

    // Validate coefficient proofs. This corresponds to Verification 2
    // (Guardian public-key validation) in the specification 2.0.0.
    // This includes the validation of commitments.
    let coefficients = &gpki.coefficient_commitments().0;
    let proofs = gpki.coefficient_proofs();
    for (j, (proof, commitment)) in proofs.iter().zip(coefficients).enumerate() {
        if proof
            .validate(fixed_parameters, i as u32, j as u32, commitment)
            .is_err()
        {
            return Err(PublicKeyValidationError::InvalidProof { j });
        }
    }

    Ok(())
}
