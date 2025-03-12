// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]

//! This module provides the [`GuardianPublicKeyTrait`] trait
//! which allows read access and validation of public key data.

use std::sync::Arc;

use util::algebra::GroupElement;

use crate::{
    errors::EgError,
    fixed_parameters::FixedParameters,
    guardian::{AsymmetricKeyPart, GuardianIndex, GuardianKeyPartId, GuardianKeyPurpose},
    guardian_coeff_proof::CoefficientsProof,
    guardian_secret_key::{CoefficientCommitment, CoefficientCommitments},
    resource::{ProduceResource, ProduceResourceExt},
};

/// Trait providing access to data common to both
/// [`GuardianPublicKey`](crate::guardian_public_key::GuardianPublicKey) and
/// [`GuardianSecretKey`](crate::guardian_secret_key::GuardianSecretKey).
///
/// It also allows to validate both types of keys (cf. Verification `2` in Section `3.2.2`).
#[async_trait::async_trait(?Send)]
pub trait GuardianKeyInfoTrait {
    /// Guardian key ID, describing the guardian number, the key purpose, and the
    /// asymmetric key part.
    fn guardian_key_id(&self) -> &GuardianKeyPartId;

    /// Guardian index number, 1 <= i <= [`n`](crate::varying_parameters::VaryingParameters::n).
    fn guardian_index(&self) -> GuardianIndex {
        self.guardian_key_id().guardian_ix
    }

    /// Guardian number, 1 <= i <= [`n`](crate::varying_parameters::VaryingParameters::n).
    fn i(&self) -> GuardianIndex {
        self.guardian_key_id().guardian_ix
    }

    /// [Key purpose](crate::guardian::GuardianKeyPurpose)
    fn key_purpose(&self) -> GuardianKeyPurpose {
        self.guardian_key_id().key_purpose
    }

    /// Asymmetric part, 'Public' or 'Secret'.
    fn asymmetric_key_part(&self) -> AsymmetricKeyPart {
        self.guardian_key_id().asymmetric_key_part
    }

    /// Short name with which to refer to the guardian. Should not have any line breaks.
    ///
    /// Optional, may be blank.
    fn name(&self) -> &str;

    /// Published polynomial coefficient commitments.
    ///
    /// EGDS 2.1.0 bottom of pg. 21 "K_{i,j}"
    fn coefficient_commitments(&self) -> &CoefficientCommitments;

    /// Proof of knowledge of a specific [`GuardianSecretKey`], and
    /// commitment to a specific public communication key.
    ///
    /// EGDS 2.1.0 bottom of pg. 23.
    fn opt_coefficients_proof(&self) -> &Option<Arc<CoefficientsProof>>;

    /// Returns the actual public key of the [`GuardianPublicKey`].
    ///
    /// The return value corresponds to commitment `K_{i,0}` in Section `3.2.2`.
    fn public_key_k_i_0(&self) -> Result<&GroupElement, PublicKeyValidationError> {
        let coeff_commitment_0: &CoefficientCommitment = self
            .coefficient_commitments()
            .iter()
            .next()
            .ok_or(PublicKeyValidationError::NoCommitments { i: self.i() })?;

        Ok(&coeff_commitment_0.0)
    }

    /// Returns the actual public key as a big-endian byte vector
    /// of length [`Group::p_len_bytes`](util::algebra::Group::p_len_bytes).
    fn to_be_bytes_left_pad(
        &self,
        fixed_parameters: &FixedParameters,
    ) -> Result<Vec<u8>, PublicKeyValidationError> {
        let group = fixed_parameters.group();
        let v = self.public_key_k_i_0()?.to_be_bytes_left_pad(group);
        Ok(v)
    }

    /// Validates that the thing implementing [`GuardianPublicKeyTrait`] is well-formed
    /// and conforms to the election parameters.
    ///
    /// The arguments are:
    ///
    /// - `produce_resource` - an implementation of [`ProduceResourceExt`](crate::resource::ProduceResourceExt)
    ///
    /// This corresponds to Verification `2` in Section `3.2.2`.
    async fn validate_public_key_info_to_election_parameters(
        &self,
        produce_resource: &(dyn ProduceResource + Send + Sync + 'static),
    ) -> Result<(), PublicKeyValidationError> {
        let election_parameters = produce_resource.election_parameters().await?;
        let election_parameters = election_parameters.as_ref();
        let varying_parameters = &election_parameters.varying_parameters();

        let n = varying_parameters.n().as_quantity();
        let k = varying_parameters.k().as_quantity();

        let i_guardian_ix = self.i();
        if i_guardian_ix > varying_parameters.n() {
            return Err(PublicKeyValidationError::IndexOutOfRange {
                i: i_guardian_ix.into(),
                n,
            });
        }

        if self.name().contains('\n') {
            return Err(PublicKeyValidationError::NameContainsNewLine);
        }

        let c_len = self.coefficient_commitments().len();
        if c_len != k {
            return Err(PublicKeyValidationError::InadequateNumberOfCommitments {
                i: self.i(),
                k,
                c_len,
            });
        }

        //? TODO validate each of self.coefficient_commitments()

        //? TODO validate/verify self.opt_coefficients_proof()

        /*
        // Validate coefficient proofs. This corresponds to Verification 2
        // (Guardian public-key validation) in the specification 2.1.0. [TODO check ref]
        // This includes the validation of commitments.
        let commitments: &Vec<_> = self.coefficient_commitments();
        let proofs = self.opt_coefficients_proofs();
        for (j, (proof, commitment)) in proofs.iter().zip(commitments).enumerate() {
            if proof
                .validate(election_parameters, i_guardian_ix, j as u32, commitment)
                .is_err()
            {
                return Err(PublicKeyValidationError::InvalidProof { j });
            }
        }
        // */

        Ok(())
    }
}

/// Represents errors occurring during the validation of a public key.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum PublicKeyValidationError {
    /// Occurs if the guardian's index is out of bounds.
    #[error("Guardian number i={i} is not in the range 1 <= i <= n={n}")]
    IndexOutOfRange { i: usize, n: usize },

    /// Occurs if the guardian's name contains a newline character.
    #[error("The guardian's name must not contain a newline.")]
    NameContainsNewLine,

    /// Occurs if the guardian's commitment vector is empty.
    #[error("Guardian's public key contains no coefficient commitments.")]
    NoCommitments { i: GuardianIndex },

    /// Occurs if the guardian's commitment vector is not of length [`k`](crate::varying_parameters::VaryingParameters::k).
    #[error(
        "Guardian `{i}` public key contains `{c_len}` coefficient commitments, expected k=`{k}`."
    )]
    InadequateNumberOfCommitments {
        i: GuardianIndex,
        k: usize,
        c_len: usize,
    },

    /// Occurs if a coefficient proof is invalid.
    #[error("The proof for coefficient {j} is invalid.")]
    InvalidProof { j: usize },

    #[error("Validation error: {0}")]
    EgError(#[from] Box<EgError>),
}

impl From<EgError> for PublicKeyValidationError {
    fn from(e: EgError) -> Self {
        PublicKeyValidationError::EgError(Box::new(e))
    }
}
