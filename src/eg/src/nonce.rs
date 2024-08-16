// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use util::algebra::FieldElement;

use crate::{
    contest_data_fields::ContestDataFieldIndex,
    election_manifest::ContestIndex,
    hash::{eg_h, HValue},
    pre_voting_data::PreVotingData,
};

//-------------------------------------------------------------------------------------------------|

/// Encryption of a [`ContestDataFieldPlaintext`] requires a nonce ξ_i_j that is `mod q`.
/// Used when for producing proofs about the plaintext.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub struct NonceFE(pub FieldElement);

impl NonceFE {
    /// Make a new `NonceField` from a `FieldElement`.
    pub fn from_field_element(field_element: FieldElement) -> Self {
        Self(field_element)
    }

    /// Design Specification v2.0
    ///
    /// 3.3.2 Generation of encryption nonces
    ///
    /// Equation 25:
    ///
    ///  ξi,j = H(H_E; 0x20, ξ_B, Λ_i, λ_j)
    ///
    #[allow(non_snake_case)]
    pub fn derive_from_xi_B(
        pre_voting_data: &PreVotingData,
        ballot_nonce_xi_B: HValue,
        contest_i: ContestIndex,
        data_field_j: ContestDataFieldIndex,
    ) -> Self {
        let field = &pre_voting_data.parameters.fixed_parameters.field;

        let label_i = contest_i.get_one_based_u32();
        let label_j = data_field_j.get_one_based_u32();

        let mut v = vec![0x20];
        v.extend_from_slice(ballot_nonce_xi_B.as_ref());
        v.extend_from_slice(&label_i.to_be_bytes());
        v.extend_from_slice(&label_j.to_be_bytes());

        let nonce = eg_h(&pre_voting_data.hashes_ext.h_e, &v);

        // Ensures mod q
        Self(FieldElement::from_bytes_be(nonce.0.as_slice(), field))
    }

    //? /// The nonce with xi equal to 0.
    // pub fn zero() -> FieldElement {
    //     FieldElement {
    //         xi: ScalarField::zero(),
    //     }
    // }
}

impl AsRef<FieldElement> for NonceFE {
    fn as_ref(&self) -> &FieldElement {
        &self.0
    }
}

impl From<FieldElement> for NonceFE {
    fn from(fe: FieldElement) -> Self {
        NonceFE::from_field_element(fe)
    }
}

impl From<NonceFE> for FieldElement {
    fn from(nonce: NonceFE) -> Self {
        nonce.0
    }
}
