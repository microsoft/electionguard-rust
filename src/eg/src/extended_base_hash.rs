// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    eg::Eg,
    errors::EgResult,
    guardian::GuardianKeyPurpose,
    hash::{HValue, SpecificHValue},
    serializable::SerializableCanonical,
};

//=================================================================================================|

#[allow(non_camel_case_types)]
pub struct ExtendedBaseHash_tag;

/// `H_E`, the extended base hash.
///
/// EGDS 2.1.0 sec. 3.4.3 eq. 30 pg. 28
#[allow(non_camel_case_types)]
pub type ExtendedBaseHash_H_E = SpecificHValue<ExtendedBaseHash_tag>;

/// The [`ExtendedBaseHash`](crate::extended_base_hash::ExtendedBaseHash), `H_E`.
///
/// EGDS 2.1.0 sec. 3.4.3 eq. 30 pg. 28
#[allow(non_camel_case_types)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedBaseHash {
    /// Extended base hash.
    h_e: ExtendedBaseHash_H_E,
}

impl ExtendedBaseHash {
    /// `H_E`.
    pub fn h_e(&self) -> &ExtendedBaseHash_H_E {
        &self.h_e
    }

    /// Computes the [`ExtendedBaseHash`], H_E.
    ///
    /// EGDS 2.1.0 sec. 3.2.3 eq. 30 pg. 28
    ///
    /// - `H_E = H(H_B; 0x14, K, K_hat)`
    pub fn compute(eg: &Eg) -> EgResult<ExtendedBaseHash> {
        let fixed_parameters = eg.fixed_parameters()?;
        let fixed_parameters = &fixed_parameters;
        let hashes = eg.hashes()?;
        let jvepk_k = eg.joint_vote_encryption_public_key_k()?;
        let jbdepk_k_hat = eg.joint_ballot_data_encryption_public_key_k_hat()?;

        // Computation of the extended base hash H_E.
        // EGDS 2.1.0 sec. 3.2.3 eq. 30 pg. 28
        let expected_len_v = 1 + HValue::byte_len() + HValue::byte_len();

        let mut v = vec![0x14];
        v.extend_from_slice(jvepk_k.to_be_bytes_left_pad(fixed_parameters).as_slice());
        v.extend_from_slice(
            jbdepk_k_hat
                .to_be_bytes_left_pad(fixed_parameters)
                .as_slice(),
        );
        assert_eq!(v.len(), expected_len_v);

        let expected_len = 1025; // EGDS 2.1.0 pg. 74 (30)
        assert_eq!(v.len(), expected_len);

        let self_ = ExtendedBaseHash {
            h_e: ExtendedBaseHash_H_E::compute_from_eg_h(&hashes.h_b, &v),
        };

        Ok(self_)
    }
}

impl std::fmt::Display for ExtendedBaseHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "ExtendedBaseHash {{ h_e: {} }}", self.h_e)
    }
}

impl std::fmt::Debug for ExtendedBaseHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Display::fmt(self, f)
    }
}

impl SerializableCanonical for ExtendedBaseHash {}

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { ExtendedBaseHash, ExtendedBaseHash }

//=================================================================================================|

// Unit tests for the ElectionGuard extended hash.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use hex_literal::hex;

    use super::*;
    use crate::{eg::Eg, errors::EgResult};

    #[test]
    fn t0() -> EgResult<()> {
        let eg = &Eg::new_with_test_data_generation_and_insecure_deterministic_csprng_seed(
            "eg::extended_base_hash::t::t0",
        );

        let extended_base_hash = ExtendedBaseHash::compute(eg)?;

        // This has to be modified every time the example data election manifest is changed even a little bit.

        let expected_h_e = ExtendedBaseHash_H_E::from(hex!(
            "CF24EBAF651B6A2A25BD342C0479876D620B17F8867E6D6970A2B17FEE02826A"
        ));

        assert_eq!(
            extended_base_hash.h_e, expected_h_e,
            "hashes.h_e (left) != (right) expected_h_e"
        );

        Ok(())
    }
}
