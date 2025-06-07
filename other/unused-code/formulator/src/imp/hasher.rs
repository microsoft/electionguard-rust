// Copyright (C) Microsoft Corporation. All rights reserved.
//     MIT License
//
//    Copyright (c) Microsoft Corporation.
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE

#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]

use std::hash::{BuildHasher, Hash, Hasher};

use static_assertions::const_assert;

use rustc_stable_hash::{
    ExtendedHasher, FromStableHash, StableHasher,
    hashers::{SipHasher128, SipHasher128Hash, StableSipHasher128},
};

//=================================================================================================|

/// `rustc_stable_hash::hashers::StableSipHasher128` is non-randomized and indepent of the host
/// endianness.
pub type DefaultHasher = StableSipHasher128;

/// `rustc_stable_hash::hashers::StableSipHasher128` is non-randomized and indepent of the host
/// endianness.
pub type DefaultBuildHasher = BuildHasher_StableSipHasher128;

//=================================================================================================|

static CUSTOMIZATION_VALUES: [u64; 2] = [
    // Well-known constant 'pi' in BCD (binary coded decimal) format.
    0x_3141_5926_5358_9793_u64,
    // Well-known constant 'e' in BCD (binary coded decimal) format.
    0x_2718_2818_2845_9045_u64,
];

#[derive(Clone, Default)]
pub struct BuildHasher_StableSipHasher128(StableSipHasher128);

impl BuildHasher_StableSipHasher128 {
    /// Generate an array of [`BuildHasher_StableSipHasher128`]s.
    ///
    /// Each will be seeded differently incorporating the supplied hash seed data and
    /// its individual sequence number.
    ///
    /// So parameter `N` can be changed without changing the previous sequences.
    pub(crate) fn new_arr<const N: usize, H: Hash>(seed_data: H) -> [Self; N] {
        // A hasher initialized with some custom state and the caller-supplied seed.
        let mut ssh128 = StableSipHasher128::with_hasher(SipHasher128::new_with_keys(
            CUSTOMIZATION_VALUES[0],
            CUSTOMIZATION_VALUES[1],
        ));
        seed_data.hash(&mut ssh128);
        let ssh128 = &ssh128;

        // Customize the hasher for ix each 0..`N`
        std::array::from_fn(|ix1| {
            const_assert!(size_of::<usize>() <= size_of::<u64>());
            let ix1 = ix1 as u64;

            let mut ssh128 = ssh128.clone();
            for &cv_a in CUSTOMIZATION_VALUES.iter() {
                let u = cv_a.wrapping_mul(ix1);
                for m in [59_u64, 61] {
                    let r = u % m;
                    for &cv_b in CUSTOMIZATION_VALUES.iter() {
                        ssh128.write_u64(cv_b.rotate_left(r as u32));
                    }
                }
            }

            ssh128.write_u64(ix1);

            Self(ssh128)
        })
    }

    /// Generate a single [`BuildHasher_StableSipHasher128`].
    pub fn new<H: Hash>(seed_data: H) -> Self {
        let [self_] = Self::new_arr(seed_data);
        self_
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

impl std::hash::Hash for BuildHasher_StableSipHasher128 {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Use the hash of two arbitrary customization values generated by this hasher instance,
        // as the hash input.
        static ARBITRARY_CUSTOMIZATION_VALUES: [u64; 2] = [
            CUSTOMIZATION_VALUES[0].rotate_left(13) ^ CUSTOMIZATION_VALUES[1].rotate_left(22),
            CUSTOMIZATION_VALUES[0].rotate_left(5) ^ CUSTOMIZATION_VALUES[1].rotate_left(8),
        ];

        self.hash_one(ARBITRARY_CUSTOMIZATION_VALUES[0]).hash(state);
        self.hash_one(ARBITRARY_CUSTOMIZATION_VALUES[1]).hash(state);
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use super::*;
    use anyhow::{Context, Result, anyhow, bail, ensure};
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
