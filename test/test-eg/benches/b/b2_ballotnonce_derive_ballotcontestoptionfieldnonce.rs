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


#![allow(clippy::assertions_on_constants)]
#![allow(clippy::unwrap_used)] // This is test code
#![allow(clippy::expect_used)] // This is test code
#![allow(clippy::panic)] // This is test code
#![allow(clippy::manual_assert)] // This is test code
#![allow(non_snake_case)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code

use anyhow::{anyhow, bail, ensure, Context, Result};
use criterion::{black_box, Criterion};

use eg::nonce::BallotNonce;
use eg_artifacts_dir::{load_hashes_ext, ArtifactsDir};
use util::csprng::Csprng;

//use bench_util::{CheapPrng, CheapPrng_from_u128};

use crate::b::*;

#[rustfmt::skip]
pub fn bench(c: &mut Criterion) {
    let bench_function_id = "b2 BallotNonce::derive_contest_option_field_nonce";

    let h_ext = {
        let artifacts_dir = ArtifactsDir::new().unwrap();
        load_hashes_ext(&artifacts_dir).unwrap()
    };

    let ballot_nonce = {
        let mut csprng = Csprng::new(bench_function_id.as_ref());
        BallotNonce::generate(&mut csprng)
    };

    let i = eg::election_manifest::ContestIndex::MIN;

    let j = eg::election_manifest::ContestOptionIndex::MIN;

    let afn = [
        BallotNonce::derive_contest_option_field_nonce_a,
        BallotNonce::derive_contest_option_field_nonce_b,
        BallotNonce::derive_contest_option_field_nonce_c,
        BallotNonce::derive_contest_option_field_nonce_d,
        BallotNonce::derive_contest_option_field_nonce_e,
        BallotNonce::derive_contest_option_field_nonce_f,
    ];

    for (group_n, (warm_up_s, measurement_s, cnt_passes)) in groups_passes().enumerate() {
        let group_name = format!("{bench_function_id} g{group_n}");

        let mut group = c.benchmark_group(group_name);
        group.warm_up_time(std::time::Duration::from_secs(warm_up_s));
        group.measurement_time(std::time::Duration::from_secs(measurement_s));

        for pass_n in 1 ..= cnt_passes {
            let str_pn = if cnt_passes == 1 { String::new() } else { format!("_p{pass_n}") };

            for (ix_fn_, fn_) in afn.iter().enumerate() {
                let id = format!("dcofn_{}{str_pn}", ('a' as usize + ix_fn_.min(25)) as u8 as char);
                group.bench_function(id, |b| { b.iter(|| black_box(fn_(&ballot_nonce, &h_ext, i, j))) });
            }
        }

        group.finish()
    }
}
