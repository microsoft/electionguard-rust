// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    hash::{eg_h, HValue},
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes {
    /// Parameter base hash.
    pub h_p: HValue,

    /// Election manifest hash.
    pub h_m: HValue,

    /// Election base hash.
    pub h_b: HValue,
}

impl Hashes {
    pub fn compute(
        election_parameters: &ElectionParameters,
        election_manifest: &ElectionManifest,
    ) -> Result<Self> {
        // H_V = 322E302E30 ∥ b(0, 27)
        let h_v: HValue = [
            0x32, 0x2E, 0x30, 0x2E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
        .into();

        // Computation of the parameter base hash H_P.
        let h_p = {
            // H_P = H(HV ; 00, p, q, g)

            let mut v_pqg = vec![0x00];

            for biguint in [
                election_parameters.fixed_parameters.p.borrow(),
                election_parameters.fixed_parameters.q.borrow(),
                &election_parameters.fixed_parameters.g,
            ] {
                v_pqg.append(&mut biguint.to_bytes_be());
            }

            eg_h(&h_v, &v_pqg)
        };

        // Computation of the election manifest hash H_M.

        let h_m = {
            let mut v = vec![0x01];

            let mut v_manifest_bytes = election_manifest.to_canonical_bytes()?;
            v.append(&mut v_manifest_bytes);

            eg_h(&h_p, &v)
        };

        // Computation of the election base hash H_B.

        let h_b = {
            let mut v = vec![0x02];

            for u in [
                election_parameters.varying_parameters.n,
                election_parameters.varying_parameters.k,
            ] {
                v.extend_from_slice(&u.get_one_based_u32().to_be_bytes());
            }

            for u in [
                &election_parameters.varying_parameters.date,
                &election_parameters.varying_parameters.info,
            ] {
                v.extend_from_slice(u.as_bytes());
            }

            v.extend_from_slice(h_m.as_ref());

            eg_h(&h_p, &v)
        };

        Ok(Self { h_p, h_m, h_b })
    }

    /// Reads a `Hashes` from a `std::io::Read` and validates it.
    pub fn from_stdioread_validated(stdioread: &mut dyn std::io::Read) -> Result<Self> {
        let self_: Self =
            serde_json::from_reader(stdioread).context("Reading GuardianSecretKey")?;

        self_.validate()?;

        Ok(self_)
    }

    /// Validates that the `Hashes` is well-formed.
    /// Useful after deserialization.
    pub fn validate(&self) -> Result<()> {
        // We currently have no validation rules for this type.
        Ok(())
    }

    /// Writes a `Hashes` to a `std::io::Write`.
    pub fn to_stdiowrite(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing Hashes")
    }

    /// Reads `Hashes` from a `std::io::Read`.
    pub fn from_reader(io_read: &mut dyn std::io::Read) -> Result<Hashes> {
        serde_json::from_reader(io_read).map_err(|e| anyhow!("Error parsing Hashes: {}", e))
    }
}

impl std::fmt::Debug for Hashes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str("Hashes {\n    h_p: ")?;
        std::fmt::Display::fmt(&self.h_p, f)?;
        f.write_str(",\n    h_m: ")?;
        std::fmt::Display::fmt(&self.h_m, f)?;
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

// Unit tests for the ElectionGuard hashes.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::{
        example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters,
    };
    use hex_literal::hex;

    #[test]
    fn test_hashes() -> Result<()> {
        let election_parameters = example_election_parameters();
        let election_manifest = example_election_manifest();

        let hashes = Hashes::compute(&election_parameters, &election_manifest)?;

        let expected_h_p = HValue::from(hex!(
            "BAD5EEBFE2C98C9031BA8C36E7E4FB76DAC20665FD3621DF33F3F666BEC9AC0D"
        ));
        let expected_h_m = HValue::from(hex!(
            "2FE7EA3C2E3C42F88647B4727254F960F1BB7B0D00A6A60C21D2F8984F5090B7"
        ));
        let expected_h_b = HValue::from(hex!(
            "A522FFB66B7D0A950BB560FD48F176F0AAA5CB1A6FA9E5BA9F0543CCB945572F"
        ));

        #[cfg(test_hash_mismatch_warn_only)]
        {
            let cmp = |s, actual, expected| {
                if actual != expected {
                    eprintln!(
                        "\nWARNING FAILURE SUPPRESSED:\n{s}   actual: {:?}\n{s} expected: {:?}",
                        actual, expected
                    );
                }
            };
            cmp("h_p", hashes.h_p, expected_h_p);
            cmp("h_m", hashes.h_m, expected_h_m);
            cmp("h_b", hashes.h_b, expected_h_b);
        }
        #[cfg(not(test_hash_mismatch_warn_only))]
        {
            assert_eq!(hashes.h_p, expected_h_p);
            assert_eq!(hashes.h_m, expected_h_m);
            assert_eq!(hashes.h_b, expected_h_b);
        }

        Ok(())
    }
}
