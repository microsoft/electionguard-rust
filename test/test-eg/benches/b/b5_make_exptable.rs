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
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code

use std::borrow::Borrow;
use std::mem::{align_of, size_of};
use std::num::Wrapping;

use anyhow::{anyhow, bail, ensure, Context, Result};
use criterion::*;
use criterion::{black_box, Bencher, Criterion};
use crypto_bigint::modular::Retrieve;
use fixed_width_nonnegative::primitive_unsigned::PrimitiveUnsigned;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use rand_core::RngCore;
use rayon::prelude::*;
use static_assertions::{assert_eq_size, const_assert, const_assert_eq};

use eg::election_manifest::{ContestIndex, ContestOptionIndex};
use eg::election_parameters;
use eg::fixed_parameters::FixedParameters;
use eg::hash::HValueByteArray;
use eg::hashes_ext::HashesExt;
use eg::index::Index;
use eg::joint_election_public_key::JointElectionPublicKey;
use eg::nonce::BallotNonce;
use eg::vec1::Vec1;
use eg_artifacts_dir::{
    load_election_parameters, load_hashes_ext, load_joint_election_public_key, ArtifactsDir,
};
use util::csprng::Csprng;

use bench_util::*;

use crate::b::*;

const DEFAULT_THREADS: usize = 8;
const PASS_BENCHFN_CNT_ITERS: usize = 10;

pub(crate) fn group_pass_infos() -> Vec<GroupPassInfo> {
    [ //   warmup_s,    meas_s,    samp_sz,     passes   
    (          None,      None,         10,         1    ),
    //(          Some(1),      Some(1),         10,         1    ),
    //(          Some(2),      Some(5),         20,         1    ),
    //(          None,      None,        100,          1    ),
    //(       Some(2),    Some(5),       100,          1    ),
    //(       Some(3),   Some(10),       100,          1    ),
    ].iter()
    .map(|&(opt_warm_up_time_s, opt_target_measurement_time_s, sample_size, cnt_passes)| {
        if sample_size < 10 {
            eprintln!("\nWARN: Sample size of {sample_size} is less than the minimum recommended value of 10");
        }
        GroupPassInfo { opt_warm_up_time_s, opt_target_measurement_time_s, sample_size, cnt_passes }
    }).collect()
}

#[rustfmt::skip]
pub fn bench(c: &mut Criterion) {
    let bench_function_id = format!("b5 make exptable");

    eprintln!("\n================================================================ Bench: {bench_function_id}\n");

    let min_cnt_threads = 1;
    eprintln!("min_cnt_threads: {min_cnt_threads}");

    let max_cnt_threads = rayon::max_num_threads();
    eprintln!("Rayon max_cnt_threads: {max_cnt_threads}");

    let csprng = Csprng::new(bench_function_id.as_ref());

    let p: crybi_Nonnegative_4096 = standard_parameter_p().into();

    let vfns: Vec<(&str, Box<(dyn Fn(&u64) -> u64 + Send + Sync)>)> = vec![
        ("make_exptable_a", Box::new(make_exptable_a)),
        ("use_exptable_a", Box::new(use_exptable_a)),
    ];

    let over_fn_cnt = (1 < vfns.len()).then(|| format!(", each over {} functions", vfns.len()))
        .unwrap_or_default();

    let v_group_pass_infos = group_pass_infos();
    for (group_n, group_pass_info) in v_group_pass_infos.iter().enumerate() {
        let group_name = format!("{bench_function_id} g{group_n}");
        let cnt_passes = group_pass_info.cnt_passes;
        let pass_digits = format!("{cnt_passes}").len();

        eprintln!("\n================================================ Group {group_n} of {}", v_group_pass_infos.len());
        eprintln!("\n{group_pass_info:#?}");

        eprintln!("\nRunning {cnt_passes:0wid$} passes{over_fn_cnt}.", wid=pass_digits);

        let mut group = c.benchmark_group(group_name);
        group_pass_info.opt_warm_up_time_s.map(|s| group.warm_up_time(std::time::Duration::from_secs(s)));
        group_pass_info.opt_target_measurement_time_s.map(|s| group.measurement_time(std::time::Duration::from_secs(s)));
        group.sample_size(group_pass_info.sample_size);

        group.throughput(Throughput::Elements(PASS_BENCHFN_CNT_ITERS as u64));

        for pass_n in 1 ..= cnt_passes {
            let str_pn = (cnt_passes != 1).then(|| format!(" p{pass_n:0wid$}", wid=pass_digits))
                .unwrap_or_default();

            eprintln!("\n============================== Pass {pass_n} of {cnt_passes}{over_fn_cnt}");

            for (fn_ch, bx_fn) in &vfns {
                //let diff_cnt_threads = max_cnt_threads.saturating_sub(min_cnt_threads).max(1);
                //let cnt_threads = min_cnt_threads + (pass_n as usize % diff_cnt_threads);
                //let cnt_threads = cnt_threads.min(rayon::max_num_threads());
                let cnt_threads = 24; //cnt_threads.min(rayon::max_num_threads());

                let benchfn_id = format!("{fn_ch}{str_pn}_{cnt_threads}th");

                eprintln!("\n------------------------- bench fn {benchfn_id}\n");

                eprintln!("cnt_threads: {cnt_threads}");

                let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(cnt_threads)
                .build()
                .unwrap();
    
                let ref_fn: &_ = bx_fn.as_ref();

                let src_data = vec![0_u64; cnt_threads];
                let mut result_data = Vec::<u64>::with_capacity(cnt_threads);

                group.bench_function(benchfn_id, |b| {
                    pool.install(|| {
                        b.iter(|| {
                            src_data
                                .par_iter()
                                .map(|x| ref_fn(x))
                                .collect_into_vec(&mut result_data);
                        })
                    });
                });    
            }
        }

        group.finish();
        eprintln!("\n[group finish]");
    }

    eprintln!("\n[bench finish]");
}

//=================================================================================================|

use ::rand_core::SeedableRng;
use ::rand::Rng;

pub fn make_exptable_a(src: &u64) -> u64 {
    let mut rng = ::rand_pcg::Pcg64Mcg::seed_from_u64(*src);
    let mut result = Wrapping(0_u64);

    let p: crybi_Nonnegative_4096 = standard_parameter_p().into();

    for _ in 0..PASS_BENCHFN_CNT_ITERS {
        let exptable = ExpTable4096::new(
            p.clone(),
            standard_parameter_p_dynresidueparams_cloned(),
            4
        ).unwrap();

        result += exptable.get_something(&mut rng);
    }

    result.0
}

pub fn use_exptable_a(src: &u64) -> u64 {
    let mut rng = ::rand_pcg::Pcg64Mcg::seed_from_u64(*src);
    let mut result = Wrapping(0_u64);

    let p_exptable = standard_parameter_exptable_g_p_4();

    for _ in 0..PASS_BENCHFN_CNT_ITERS {
        let mut exp = crybi_U256::ZERO;
        for w in exp.as_words_mut() {
            *w = rng.next_u64().into();
            #[allow(arithmetic_overflow)]
            for _ in 1..(std::mem::size_of_val(w).div_ceil(8)) {
                *w <<= 64;
                *w = rng.next_u64().into();
            }
        }

        let dynresidue = p_exptable.pow(exp).unwrap();
        let words = dynresidue.as_montgomery().as_words();
        assert!(words.len() != 0);

        result += words[rng.gen_range(0..words.len())] as u64;
    }

    result.0
}

pub fn use_exptable_b(src: &u64) -> u64 {
    let mut rng = ::rand_pcg::Pcg64Mcg::seed_from_u64(*src);
    let mut result = Wrapping(0_u64);

    let p_exptable = standard_parameter_exptable_g_p_4();

    for _ in 0..PASS_BENCHFN_CNT_ITERS {
        let mut exp = crybi_U256::ZERO;
        for w in exp.as_words_mut() {
            *w = rng.next_u64().into();
            #[allow(arithmetic_overflow)]
            for _ in 1..(std::mem::size_of_val(w).div_ceil(8)) {
                *w <<= 64;
                *w = rng.next_u64().into();
            }
        }

        let dynresidue = p_exptable.pow(exp).unwrap();
        let words = dynresidue.as_montgomery().as_words();
        assert!(words.len() != 0);

        result += words[rng.gen_range(0..words.len())] as u64;
    }

    result.0
}
