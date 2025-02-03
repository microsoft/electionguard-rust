// Copyright (C) Microsoft Corporation. All rights reserved.

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::hash::{BuildHasher, Hash, Hasher};

use static_assertions::const_assert;

use rustc_stable_hash::{
    hashers::{SipHasher128, SipHasher128Hash, StableSipHasher128},
    ExtendedHasher, FromStableHash, StableHasher,
};

//=================================================================================================|

/// `rustc_stable_hash::hashers::StableSipHasher128` is non-randomized and indepent of the host
/// endianness.
pub type DefaultHasher = StableSipHasher128;

/// `rustc_stable_hash::hashers::StableSipHasher128` is non-randomized and indepent of the host
/// endianness.
pub type DefaultBuildHasher = BuildHasher_StableSipHasher128;

//=================================================================================================|

#[derive(Clone, Default)]
pub struct BuildHasher_StableSipHasher128(StableSipHasher128);

impl BuildHasher_StableSipHasher128 {
    /// Generate an array of [`BuildHasher_StableSipHasher128`]s.
    ///
    /// Each will be seeded differently incorporating the supplied hash seed data and
    /// the .
    ///
    /// So parameter N ca
    pub(crate) fn new_arr<const N: usize, H: Hash>(seed_data: H) -> [Self; N] {
        use std::hash::Hasher;

        const CUSTOMIZATION_VALUES: [u64; 2] = [
            // Well-known constant 'pi' in BCD (binary coded decimal) format.
            0x_3141_5926_5358_9793_u64,
            // Well-known constant 'e' in BCD (binary coded decimal) format.
            0x_2718_2818_2845_9045_u64,
        ];

        // A hasher initialized with some custom state and the caller-supplied seed.
        let mut s = StableSipHasher128::with_hasher(SipHasher128::new_with_keys(
            CUSTOMIZATION_VALUES[0],
            CUSTOMIZATION_VALUES[1],
        ));
        seed_data.hash(&mut s);
        let s = &s;

        // Customize the hasher for ix each 0..`N`
        std::array::from_fn(|ix1| {
            const_assert!(size_of::<usize>() <= size_of::<u64>());
            let ix1 = ix1 as u64;

            let mut s = s.clone();
            for &cv_a in CUSTOMIZATION_VALUES.iter() {
                let u = cv_a.wrapping_mul(ix1);
                for m in [59_u64, 61] {
                    let r = u % m;
                    for &cv_b in CUSTOMIZATION_VALUES.iter() {
                        s.write_u64(cv_b.rotate_left(r as u32));
                    }
                }
            }

            s.write_u64(ix1);

            Self(s)
        })
    }

    /// Simply clones the internal [`StableSipHasher128`].
    pub fn build(&self) -> StableSipHasher128 {
        self.0.clone()
    }
}

impl std::hash::BuildHasher for BuildHasher_StableSipHasher128 {
    type Hasher = StableSipHasher128;

    /// Simply clones the internal [`StableSipHasher128`].
    fn build_hasher(&self) -> Self::Hasher {
        self.build()
    }
}

impl std::fmt::Display for BuildHasher_StableSipHasher128 {
    /// Format the value suitable for user-facing output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let u: u64 = Hasher::finish(&self.0);
        write!(f, "BuildHasher_StableSipHasher128 {{ finish: {u:#018x} }}")
    }
}

impl std::fmt::Debug for BuildHasher_StableSipHasher128 {
    /// Format the value suitable for debugging output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl serde::Serialize for BuildHasher_StableSipHasher128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::{Error, SerializeStruct};

        let mut state = serializer.serialize_struct("BuildHasher_StableSipHasher128", 1)?;

        let u: u64 = Hasher::finish(&self.0);
        state.serialize_field("finish", &format!("{u:#018x}"))?;

        state.end()
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use anyhow::{anyhow, bail, ensure, Context, Result};
    use insta::{assert_debug_snapshot, assert_snapshot};
    use itertools::Itertools;

    #[test]
    fn t0() {
        const CNT_HASHERS: usize = 15;

        let bhxrs: [BuildHasher_StableSipHasher128; CNT_HASHERS] =
            BuildHasher_StableSipHasher128::new_arr(0_u64);

        assert_debug_snapshot!(bhxrs);

        let hxrs: [StableSipHasher128; CNT_HASHERS] = bhxrs
            .iter()
            .map(|bhxr| bhxr.build())
            .collect_array()
            .unwrap();

        let hvs: [[u64; 4]; CNT_HASHERS] = hxrs
            .iter()
            .map(|hxr| {
                (0_u64..)
                    .map(|ix| {
                        let mut s = hxr.clone();
                        s.write_u64(0);
                        Hasher::finish(&s)
                    })
                    .next_array()
                    .unwrap()
            })
            .collect_array()
            .unwrap();

        let mut s = String::new();
        s.push_str("Hash values: [");
        for a in hvs {
            s.push_str(&format!(
                "\n    [ {:#018x}, {:#018x}, {:#018x}, {:#018x} ],",
                a[0], a[1], a[2], a[3]
            ));
        }
        s.push_str("\n]\n");
        assert_snapshot!(s);

        // Check that each hasher produces a unique hash value.
        for i in 1..CNT_HASHERS {
            for j in 0..i {
                let hv_i = hvs[i];
                let hv_j = hvs[j];
                assert_ne!(hv_i, hv_j)
            }
        }
    }
}
