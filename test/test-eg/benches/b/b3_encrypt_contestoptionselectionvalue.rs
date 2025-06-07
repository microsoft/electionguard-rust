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
use eg::fixed_parameters::FixedParameters;
use num_bigint::BigUint;

use eg::election_parameters;
use eg::joint_election_public_key::{Ciphertext, JointElectionPublicKey};
use eg::nonce::BallotNonce;
use eg_artifacts_dir::{
    load_election_parameters, load_hashes_ext, load_joint_election_public_key, ArtifactsDir,
};
use util::algebra::FieldElement;
use util::csprng::Csprng;

//use bench_util::{CheapPrng, CheapPrng_from_u128};

use crate::b::*;

#[rustfmt::skip]
pub fn bench(c: &mut Criterion) {
    let bench_function_id = "b3 encrypt contest option field";

    let artifacts_dir = ArtifactsDir::new().unwrap();

    let mut csprng = Csprng::new(bench_function_id.as_ref());
    let csprng = &mut csprng;

    let election_parameters = load_election_parameters(&artifacts_dir, csprng).unwrap();
    let fixed_parameters: FixedParameters = election_parameters.fixed_parameters.clone();
    let h_ext = load_hashes_ext(&artifacts_dir).unwrap();

    let joint_election_public_key = load_joint_election_public_key(&artifacts_dir, &election_parameters).unwrap();

    let cof_nonce = {
        let ballot_nonce = BallotNonce::generate(csprng);

        let i = eg::election_manifest::ContestIndex::MIN;

        let j = eg::election_manifest::ContestOptionIndex::MIN;

        BallotNonce::derive_contest_option_field_nonce(&ballot_nonce, &h_ext, i, j)
    };

    let cof_nonce_biguint = BigUint::from_bytes_be(cof_nonce.0.as_slice());

    let field = &fixed_parameters.field;

    let cof_nonce_fieldelement = FieldElement::from(
        cof_nonce_biguint,
        &fixed_parameters.field );

    let afn = [
        jepk_encrypt_to_a,
        /*
        jepk_encrypt_to_b,
        // */
    ];

    for (group_n, (warm_up_s, measurement_s, cnt_passes)) in groups_passes().enumerate() {
        let group_name = format!("{bench_function_id} g{group_n}");

        let mut group = c.benchmark_group(group_name);
        group.warm_up_time(std::time::Duration::from_secs(warm_up_s));
        group.measurement_time(std::time::Duration::from_secs(measurement_s));

        for pass_n in 1 ..= cnt_passes {
            let str_pn = if cnt_passes == 1 { String::new() } else { format!("_p{pass_n}") };

            let vote: usize = pass_n;

            for (ix_fn_, fn_) in afn.iter().enumerate() {
                let id = format!("enc_{}{str_pn}", ('a' as usize + ix_fn_.min(25)) as u8 as char);
                group.bench_function(id, |b| { b.iter(|| black_box(fn_(
                    &joint_election_public_key, &fixed_parameters,
                    &cof_nonce_fieldelement,
                    vote))) });
            }
        }

        group.finish()
    }
}

fn jepk_encrypt_to_a(
    jepk: &JointElectionPublicKey,
    fixed_parameters: &FixedParameters,
    cof_nonce_fieldelement: &FieldElement,
    vote: usize,
) -> Ciphertext {
    jepk.encrypt_to(fixed_parameters, cof_nonce_fieldelement, vote)
}
