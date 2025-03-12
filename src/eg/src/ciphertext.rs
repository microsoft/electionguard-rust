// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use serde::{Deserialize, Serialize};

use util::{
    algebra::{FieldElement, Group, GroupElement},
    index::Index,
    vec1::HasIndexType,
};

use crate::{
    eg::Eg,
    election_manifest::ContestIndex,
    errors::{EgError, EgResult},
    fixed_parameters::FixedParameters,
    pre_voting_data::PreVotingData,
    selection_limits::EffectiveOptionSelectionLimit,
    zk::ProofRange,
};

#[derive(Debug, Clone, Serialize, Deserialize, Eq)]
pub struct Ciphertext {
    pub alpha: GroupElement,
    pub beta: GroupElement,
}

impl HasIndexType for Ciphertext {
    type IndexTypeParam = Ciphertext;
}

/// A 1-based index of a [`Ciphertext`] in the order it is defined in the [`ElectionManifest`](crate::election_manifest::ElectionManifest).
///
/// Same type as [`ContestOptionIndex`](crate::election_manifest::ContestOptionIndex), [`ContestOptionFieldPlaintextIndex`](crate::contest_option_fields::ContestOptionFieldPlaintextIndex), [`ContestDataFieldIndex`](crate::contest_data_fields_plaintexts::ContestDataFieldIndex), etc.
pub type CiphertextIndex = Index<Ciphertext>;

impl Ciphertext {
    /// Verify the proof that the cipher text is an encryption of 0 or 1.
    pub fn verify_ballot_correctness(
        &self,
        pre_voting_data: &PreVotingData,
        proof: &ProofRange,
        effective_option_selection_limit: EffectiveOptionSelectionLimit,
        contest_ix_for_errs: ContestIndex,
        ciphertext_ix_for_errs: CiphertextIndex,
    ) -> EgResult<()> {
        if proof.verify(
            pre_voting_data,
            self,
            effective_option_selection_limit.into(),
        ) {
            Ok(())
        } else {
            Err(
                EgError::BallotContestFieldCiphertextDoesNotVerify_ProofDoesNotVerify {
                    contest_ix: contest_ix_for_errs,
                    ciphertext_ix: ciphertext_ix_for_errs,
                },
            )
        }
    }

    /// The ciphertext with alpha and beta equal to 1. This is the neutral element
    /// of ciphertexts with respect to component-wise multiplication.
    pub fn one() -> Ciphertext {
        Ciphertext {
            alpha: Group::one(),
            beta: Group::one(),
        }
    }

    /// Scale a ciphertext by a factor. The scaling of an encryption of `x` with a factor `k`
    /// gives an encryption of `k*x`.
    pub fn scale(&self, fixed_parameters: &FixedParameters, factor: &FieldElement) -> Ciphertext {
        let group = fixed_parameters.group();
        let alpha = self.alpha.exp(factor, group);
        let beta = self.beta.exp(factor, group);

        Ciphertext { alpha, beta }
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.alpha == other.alpha && self.beta == other.beta
    }
}
