// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::manual_assert)]

use std::borrow::Borrow;

use serde::{Deserialize, Serialize};

use crate::{
    election_manifest::ElectionManifest,
    election_parameters::ElectionParameters,
    hash::{eg_h, HValue},
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes {
    /// Parameter base hash.
    h_p: HValue,

    /// Election manifest hash.
    h_m: HValue,

    /// Election base hash.
    h_b: HValue,
    //? TODO?
    // /// Extended base hash.
    // h_e: HValue,
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

impl Hashes {
    #[allow(dead_code)] //? TODO: Remove this
    pub fn new(
        election_parameters: &ElectionParameters,
        election_manifest: &ElectionManifest,
    ) -> Self {
        // Computation of the parameter base hash H_P.
        let h_p = {
            // "B1 = 00 ∥ b(p, 512) ∥ b(q, 32) ∥ b(g, 512) ∥ b(n, 2) ∥ b(k, 2)"

            let mut v_pqgnk = vec![0x00];

            for biguint in [
                election_parameters.fixed_parameters.p.borrow(),
                election_parameters.fixed_parameters.q.borrow(),
                election_parameters.fixed_parameters.g.borrow(),
            ] {
                v_pqgnk.append(&mut biguint.to_bytes_be());
            }

            for u in [
                election_parameters.varying_parameters.n,
                election_parameters.varying_parameters.k,
            ] {
                v_pqgnk.extend_from_slice(&u.to_be_bytes());
            }

            eg_h(&HValue::default(), &v_pqgnk)
        };

        // Computation of the manifest hash H_M.

        let h_m = {
            let mut v = vec![0x01];

            let mut v_manifest_bytes = election_manifest.to_canonical_bytes();
            v.append(&mut v_manifest_bytes);

            eg_h(&h_p, &v)
        };

        // Computation of the base hash H_B.

        let h_b = {
            let mut v = vec![0x02];

            let v_date_bytes = election_parameters.varying_parameters.date.as_bytes();
            v.extend_from_slice(v_date_bytes);

            let v_info_bytes = election_parameters.varying_parameters.info.as_bytes();
            v.extend_from_slice(v_info_bytes);

            v.extend(h_m.as_ref().iter());

            eg_h(&h_p, &v)
        };

        //? TODO?
        // // Computation of the extended base hash H_E.
        //
        // let h_e = {
        //     evaluate_h(HKEY_ALL_ZEROES, &v_pqgnk) //? TODO
        // };

        Self {
            h_p,
            h_m,
            h_b, //, h_e
        }
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

// Unit tests for the ElectionGuard hash.
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        example_election_manifest::example_election_manifest,
        example_election_parameters::example_election_parameters,
    };
    use hex_literal::hex;

    #[test]
    fn test_hashes() {
        let election_parameters = example_election_parameters();
        let election_manifest = example_election_manifest();

        let hashes = Hashes::new(&election_parameters, &election_manifest);

        let expected_h_p = HValue::from(hex!(
            "eb16f520cd4776961e1e73947f34649413b822661b992dde7f546480e20501b6"
        ));
        let expected_h_m = HValue::from(hex!(
            "7b7cda7b05bddef7381b890a76379de4a0e193f68b9204cd2e2db8d743326ad7"
        ));
        let expected_h_b = HValue::from(hex!(
            "763b1e6ab4f82494445173861581304fa68413744764359e9984d0a4a32b22d0"
        ));

        assert_eq!(hashes.h_p, expected_h_p);
        assert_eq!(hashes.h_m, expected_h_m);
        assert_eq!(hashes.h_b, expected_h_b);
    }
}
