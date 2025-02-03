// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use util::algebra_utils::to_be_bytes_left_pad;

use crate::{
    eg::Eg,
    election_parameters::ElectionParameters,
    errors::EgResult,
    hash::{eg_h, HValue},
    serializable::SerializableCanonical,
};

/// Parameter base hash (Eq. 4 in EGDS 2.1.0 Section 3.1.2)
/// This is used to compute guardian keys..
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterBaseHash {
    pub h_p: HValue,
}

impl ParameterBaseHash {
    pub fn compute(election_parameters: &ElectionParameters) -> Self {
        let fixed_parameters = election_parameters.fixed_parameters();
        let varying_parameters = &election_parameters.varying_parameters();
        let field = fixed_parameters.field();
        let group: &util::algebra::Group = fixed_parameters.group();

        // H_V = 0x76322E312E30 | b(0, 26)
        let h_v: HValue = [
            // This is the UTF-8 encoding of "v2.1.0"
            0x76, 0x32, 0x2E, 0x31, 0x2E, 0x30, // Padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
        .into();

        // v = 0x00 | b(p,512)| b(q,32) | b(g,512) | b(n,4) | b(k,4)
        let mut v = vec![0x00];
        v.extend_from_slice(to_be_bytes_left_pad(&group.modulus(), group.p_len_bytes()).as_slice());
        v.extend_from_slice(to_be_bytes_left_pad(&field.order(), field.q_len_bytes()).as_slice());
        v.extend_from_slice(group.generator().to_be_bytes_left_pad(group).as_slice());
        v.extend(varying_parameters.n().get_one_based_4_be_bytes());
        v.extend(varying_parameters.k().get_one_based_4_be_bytes());

        let expected_len = 1065; // EGDS 2.1.0 pg. 74 (4)
        assert_eq!(v.len(), expected_len);

        let h_p = eg_h(&h_v, &v);

        Self { h_p }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes {
    /// Parameter base hash.
    pub h_p: HValue,

    /// Election base hash.
    pub h_b: HValue,
}

impl Hashes {
    /// Computes the [`Hashes`].
    pub fn compute(eg: &Eg) -> EgResult<Hashes> {
        let election_parameters = eg.election_parameters()?;
        let election_parameters = election_parameters.as_ref();

        let election_manifest = eg.election_manifest()?;
        let election_manifest = election_manifest.as_ref();

        // Computation of the base parameter hash H_P.
        let h_p = ParameterBaseHash::compute(election_parameters).h_p;

        // Computation of the election base hash H_B.
        let h_b = {
            let mut v = vec![0x01];

            let mut v_manifest_bytes = election_manifest.to_canonical_bytes()?;
            v.append(&mut v_manifest_bytes);

            let expected_len = 5 + v_manifest_bytes.len(); // EGDS 2.1.0 pg. 74 (5)
            assert_eq!(v.len(), expected_len);

            eg_h(&h_p, &v)
        };

        Ok(Hashes { h_p, h_b })
    }

    /// Parameter base hash.
    pub fn h_p(&self) -> &HValue {
        &self.h_p
    }

    /// Election base hash.
    pub fn h_b(&self) -> &HValue {
        &self.h_b
    }
}

impl std::fmt::Debug for Hashes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str("Hashes {\n    h_p: ")?;
        std::fmt::Display::fmt(&self.h_p, f)?;
        f.write_str(",\n    h_b: ")?;
        std::fmt::Display::fmt(&self.h_b, f)?;
        f.write_str(" }")
    }
}

impl std::fmt::Display for Hashes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Debug::fmt(self, f)
    }
}

impl SerializableCanonical for Hashes {}

crate::impl_Resource_for_simple_ElectionDataObjectId_validated_type! { Hashes, Hashes }

//-------------------------------------------------------------------------------------------------|

// Unit tests for the ElectionGuard hashes.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use anyhow::{Context, Result};
    use hex_literal::hex;

    use super::*;
    use crate::eg::Eg;

    #[test]
    fn t0() -> Result<()> {
        let eg = &{
            let mut config = crate::eg::EgConfig::new();
            config.use_insecure_deterministic_csprng_seed_str("eg::hashes::test::t0");
            config.enable_test_data_generation_n_k(5, 3)?;
            Eg::from(config)
        };

        let hashes = Hashes::compute(eg).with_context(|| "Hashes::compute() failed")?;

        // These hashes are to get notified if the hash computation is changed. They have
        // not been computed externally.

        let expected_h_p = HValue::from(hex!(
            "2B3B025E50E09C119CBA7E9448ACD1CABC9447EF39BF06327D81C665CDD86296"
        ));

        let expected_h_b = HValue::from(hex!(
            "D2D97122C932F34EC8591E06252EDB38C7953D0B7F4013907432DDC6B0D15048"
        ));

        assert_eq!(
            hashes.h_p, expected_h_p,
            "hashes.h_p (left) != (right) expected_h_p"
        );
        assert_eq!(
            hashes.h_b, expected_h_b,
            "hashes.h_b (left) != (right) expected_h_b"
        );

        Ok(())
    }
}
