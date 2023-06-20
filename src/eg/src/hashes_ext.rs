// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use serde::{Deserialize, Serialize};

use crate::{
    election_parameters::ElectionParameters,
    hash::{eg_h, HValue},
    hashes::Hashes,
    joint_election_public_key::JointElectionPublicKey,
    key::PublicKey,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashesExt {
    /// Extended base hash.
    h_e: HValue,
}

impl HashesExt {
    pub fn new(
        election_parameters: &ElectionParameters,
        hashes: &Hashes,
        joint_election_public_key: &JointElectionPublicKey,
        guardian_public_keys: &[PublicKey],
    ) -> Self {
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;

        let n = varying_parameters.n as usize;
        let k = varying_parameters.k as usize;

        assert_eq!(guardian_public_keys.len(), n);

        // Computation of the extended base hash H_E.

        let h_e = {
            // B1 = 12 ∥ b(K, 512) ∥ b(K1,0, 512) ∥ b(K1,1, 512) ∥ · · · ∥ b(Kn,k−1, 512)
            let mut v = vec![0x12];

            // K = election public key
            v.append(&mut joint_election_public_key.to_be_bytes_len_p(fixed_parameters));

            for public_key in guardian_public_keys.iter() {
                let coefficient_commitments = public_key.coefficient_commitments();
                for coefficient_commitment in coefficient_commitments.0.iter() {
                    v.append(&mut coefficient_commitment.to_be_bytes_len_p(fixed_parameters));
                }
            }

            // len(B1) = 1 + (n · k + 1) · 512
            let expected_mod_p_values = 1 + n * k;
            let expected_len = 1 + expected_mod_p_values * fixed_parameters.l_p_bytes();
            debug_assert_eq!(v.len(), expected_len);

            // HE = H(HB; 12, K, K1,0, K1,1, . . . , Kn,k−2, Kn,k−1) (20)
            // B0 = H_B
            eg_h(&hashes.h_b, &v)
        };

        Self { h_e }
    }

    /// Returns a pretty JSON `String` representation of the `Hashes`.
    /// The final line will end with a newline.
    pub fn to_json(&self) -> String {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }
}

impl std::fmt::Display for HashesExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "HashesExt {{ h_e: {} }}", self.h_e)
    }
}

impl std::fmt::Debug for HashesExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Display::fmt(self, f)
    }
}

// Unit tests for the ElectionGuard extended hash.
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters,
        joint_election_public_key::JointElectionPublicKey, key::PrivateKey,
    };
    use hex_literal::hex;
    use std::borrow::Borrow;
    use util::csprng::Csprng;

    #[test]
    fn test_hashes_ext() {
        let mut csprng = Csprng::new(b"test_hashes_ext");

        let election_manifest = example_election_manifest();

        let election_parameters = example_election_parameters();
        let fixed_parameters = &election_parameters.fixed_parameters;
        let varying_parameters = &election_parameters.varying_parameters;

        let hashes = Hashes::new(&election_parameters, &election_manifest);

        let n = varying_parameters.n as usize;
        //let k = varying_parameters.k as usize;

        let guardian_private_keys = (0..n)
            .map(|_i| PrivateKey::generate(&mut csprng, &election_parameters))
            .collect::<Vec<_>>();

        let guardian_public_keys = guardian_private_keys
            .iter()
            .map(|private_key| private_key.make_public_key())
            .collect::<Vec<_>>();

        let joint_election_public_key =
            JointElectionPublicKey::compute(fixed_parameters, &guardian_public_keys);

        assert!(&joint_election_public_key.0 < fixed_parameters.p.borrow());

        let hashes_ext = HashesExt::new(
            &election_parameters,
            &hashes,
            &joint_election_public_key,
            guardian_public_keys.as_slice(),
        );

        let expected_h_e = HValue::from(hex!(
            "06538A5C900569D65474908D57E084F432CCCB69674A694DAD30200F0E4B10B8"
        ));
        assert_eq!(hashes_ext.h_e, expected_h_e);
    }
}
