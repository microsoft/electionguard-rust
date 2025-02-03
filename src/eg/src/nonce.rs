// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use util::algebra::{FieldElement, ScalarField};

use crate::{
    ballot::BallotNonce_xi_B,
    ballot::HValue_H_I,
    contest_data_fields_plaintexts::ContestDataFieldIndex,
    eg::Eg,
    election_manifest::ContestIndex,
    hash::{eg_h, eg_h_q, HValue},
    pre_voting_data::PreVotingData,
};

/// EG DS v2.1.0 sec 3.3.3 Generation of the ... encryption nonces
///
/// Equation 33:
///
///  ξi,j = H(H_i; 0x21, i, j, ξ_B)
///
#[allow(non_snake_case)]
pub fn derive_xi_i_j_as_hvalue(
    field: &ScalarField,
    h_i: &HValue_H_I,
    ballot_nonce_xi_B: &BallotNonce_xi_B,
    i_contest_ix: ContestIndex,
    j_data_field_ix: ContestDataFieldIndex,
) -> HValue {
    let mut v = vec![0x21];
    v.extend(i_contest_ix.get_one_based_4_be_bytes());
    v.extend(j_data_field_ix.get_one_based_4_be_bytes());
    v.extend_from_slice(ballot_nonce_xi_B.as_ref());

    let expected_len = 41; // EGDS 2.1.0 pg. 75 (33)
    assert_eq!(v.len(), expected_len);

    // Ensures mod q
    eg_h_q(h_i, &v, field)
}

/// Encryption of a [`ContestOptionFieldPlaintext`](crate::contest_option_fields::ContestOptionFieldPlaintext) requires a nonce ξ_i_j that is `mod q`.
/// Used when for producing proofs about the plaintext.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub struct NonceFE(FieldElement);

impl NonceFE {
    /// Derive FieldElement xi_i_j derived from xi_B
    #[allow(non_snake_case)]
    pub fn new_xi_i_j(
        field: &ScalarField,
        h_i: &HValue_H_I,
        ballot_nonce_xi_B: &BallotNonce_xi_B,
        contest_i: ContestIndex,
        data_field_j: ContestDataFieldIndex,
    ) -> Self {
        let xi_i_j =
            derive_xi_i_j_as_hvalue(field, h_i, ballot_nonce_xi_B, contest_i, data_field_j);
        Self(FieldElement::from_bytes_be(&xi_i_j.0, field))
    }

    /// Make a new `NonceField` from a `FieldElement`.
    pub fn from_field_element(field_element: FieldElement) -> Self {
        Self(field_element)
    }

    //? /// The nonce with xi equal to 0.
    // pub fn zero() -> FieldElement {
    //     FieldElement {
    //         xi: ScalarField::zero(),
    //     }
    // }
}

impl AsRef<NonceFE> for NonceFE {
    #[inline]
    fn as_ref(&self) -> &NonceFE {
        self
    }
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
