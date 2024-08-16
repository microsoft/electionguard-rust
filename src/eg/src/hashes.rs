// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::vec;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use util::algebra_utils::to_be_bytes_left_pad;

use crate::{
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    errors::EgResult,
    fixed_parameters::FixedParameters,
    hash::{eg_h, HValue},
    serializable::{SerializableCanonical, SerializablePretty},
};

/// Parameter base hash (cf. Section 3.1.2 in Specs 2.0.0)
/// This is used to compute guardian keys which can be independent of the election (manifest).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterBaseHash {
    pub h_p: HValue,
}

impl ParameterBaseHash {
    pub fn compute(fixed_parameters: &FixedParameters) -> Self {
        let field = &fixed_parameters.field;
        let group = &fixed_parameters.group;

        // H_V = 0x76322E302E30 | b(0, 26)
        let h_v: HValue = [
            // This is the UTF-8 encoding of "v2.0.0"
            0x76, 0x32, 0x2E, 0x30, 0x2E, 0x30, // Padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
        .into();

        // v = 0x00 | b(p,512)| b(q,32) | b(g,512)
        let mut v = vec![0x00];
        v.extend_from_slice(to_be_bytes_left_pad(&group.modulus(), group.p_len_bytes()).as_slice());
        v.extend_from_slice(to_be_bytes_left_pad(&field.order(), field.q_len_bytes()).as_slice());
        v.extend_from_slice(group.generator().to_be_bytes_left_pad(group).as_slice());
        let h_p = eg_h(&h_v, &v);

        Self { h_p }
    }
}

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
    ) -> EgResult<Self> {
        // Computation of the base parameter hash H_P.
        let h_p = ParameterBaseHash::compute(&election_parameters.fixed_parameters).h_p;

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

    /// Reads `Hashes` from a `std::io::Read`.
    pub fn from_reader(io_read: &mut dyn std::io::Read) -> Result<Hashes> {
        serde_json::from_reader(io_read).map_err(|e| anyhow!("Error parsing Hashes: {}", e))
    }
}

impl SerializablePretty for Hashes {}

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

//-------------------------------------------------------------------------------------------------|

// Unit tests for the ElectionGuard hashes.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        ballot_style::BallotStyle,
        election_manifest::{Contest, ContestIndex, ContestOption},
        example_election_parameters::example_election_parameters,
        guardian::GuardianIndex,
        selection_limit::OptionSelectionLimit,
        standard_parameters::STANDARD_PARAMETERS,
        varying_parameters::{BallotChaining, VaryingParameters},
    };
    use hex_literal::hex;

    #[test]
    fn test_parameter_base_hash() {
        let fixed_parameters = example_election_parameters().fixed_parameters;
        let hash = ParameterBaseHash::compute(&fixed_parameters);
        let expected_h_p = HValue::from(hex!(
            "2B3B025E50E09C119CBA7E9448ACD1CABC9447EF39BF06327D81C665CDD86296"
        ));
        assert_eq!(hash.h_p, expected_h_p);
    }

    fn simple_election_manifest() -> ElectionManifest {
        fn imp_() -> EgResult<ElectionManifest> {
            let contests = [
                // Contest index 1:
                Contest {
                    opt_contest_ix: None,
                    label: "Contest01".to_string(),
                    selection_limit: 1_u8.into(),
                    contest_options: [
                        ContestOption {
                            opt_contest_ix: None,
                            opt_contest_option_ix: None,
                            label: "SelectionA".to_string(),
                            selection_limit: OptionSelectionLimit::Limit(1),
                        },
                        ContestOption {
                            opt_contest_ix: None,
                            opt_contest_option_ix: None,
                            label: "SelectionB".to_string(),
                            selection_limit: OptionSelectionLimit::LimitedOnlyByContest,
                        },
                    ]
                    .try_into()
                    .unwrap(),
                },
            ]
            .try_into()
            .unwrap();

            let ballot_styles = [BallotStyle {
                opt_ballot_style_ix: Some(1.try_into()?),
                label: "BallotStyle01".to_string(),
                contests: BTreeSet::from(
                    [1u32].map(|ix1| ContestIndex::from_one_based_index(ix1).unwrap()),
                ),
            }]
            .try_into()
            .unwrap();

            ElectionManifest::new("AElection".to_string(), contests, ballot_styles)
        }
        imp_().unwrap()
    }

    fn simple_election_parameters() -> ElectionParameters {
        let fixed_parameters: FixedParameters = (*STANDARD_PARAMETERS).clone();

        let n = 5;
        let k = 3;

        // `unwrap()` is justified here because these values are fixed.
        #[allow(clippy::unwrap_used)]
        let n = GuardianIndex::from_one_based_index(n).unwrap();
        #[allow(clippy::unwrap_used)]
        let k = GuardianIndex::from_one_based_index(k).unwrap();

        let varying_parameters = VaryingParameters {
            n,
            k,
            date: "1212-12-12".to_string(),
            info: "Testing".to_string(),
            ballot_chaining: BallotChaining::Prohibited,
        };

        ElectionParameters {
            fixed_parameters,
            varying_parameters,
        }
    }

    #[test]
    fn test_hashes() -> Result<()> {
        let election_parameters = simple_election_parameters();
        let election_manifest = simple_election_manifest();

        let hashes = Hashes::compute(&election_parameters, &election_manifest)?;

        let expected_h_p = HValue::from(hex!(
            "2B3B025E50E09C119CBA7E9448ACD1CABC9447EF39BF06327D81C665CDD86296"
        ));
        // These hashes are to get notified if the hash computation is changed. They have
        // not been computed externally.
        let expected_h_m = HValue::from(hex!(
            "CC38E1C22E7768ABD6D5377B536E2E25F5C5AE8BE0F9329CD6E8A333AC938F30"
        ));
        let expected_h_b = HValue::from(hex!(
            "2AE3ABD11843AA8AC228FAFA8B5C196A2D9C47090F5450BC0DECF15524963B6D"
        ));

        assert_eq!(hashes.h_p, expected_h_p);
        assert_eq!(hashes.h_m, expected_h_m);
        assert_eq!(hashes.h_b, expected_h_b);

        Ok(())
    }
}
